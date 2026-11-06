#!/usr/bin/env python3
"""Test the CVN guest agent policy. Called by validate.sh; runnable alone.

    python3 policy-tests.py measured-policy.rego

Two halves, and the first matters as much as the second.

PHASE 0 builds three request fixtures from values measured on a live node and
requires the policy to ADMIT them. Without this, a policy that refused
*everything* would score a perfect run below, which is exactly the failure mode
that cost three hours on 4 Nov. If phase 0 fails, the run aborts rather than
reporting a wall of passes.

PHASES 1-2 take each admitting fixture, apply exactly ONE mutation, and require
a DENY. One mutation from a known-good baseline is what makes a refusal
attributable; a hand-written negative fixture can deny for a reason unrelated
to the control it claims to test. A mutation that leaves the fixture unchanged
is reported as a TEST BUG, not as a policy gap.

PHASE 3 mutates the POLICY instead of the input, to show each deliberate
exception is load-bearing rather than quietly widening the rules.

Limits, stated rather than left to be discovered:
  - A denial is not proven to come from the intended rule.
  - Capabilities and environment are read back out of the policy when building
    fixtures, so those two dimensions are self-consistent by construction.
    Mounts, storages, working directory, devices and path masks are measured
    literals.
  - Capability ADDITION cannot be tested: the pinned set is already the
    complete 41-capability Linux set, because the container is privileged.
    Removal and substitution are tested.
  - opa is not regorus. The agent evaluates with regorus and the dialects
    differ slightly, so a pass here is necessary, not sufficient.

No fixture data ships with this file. Everything is generated into a temporary
directory from the policy plus the measured literals below, and deleted after.

Needs opa on PATH.
"""
import copy, json, os, re, shutil, subprocess, sys, tempfile

def build_fixtures(pol_path, outdir):
    """Build the three positive fixtures from measured values.

    Caps and env are read back out of the policy rather than retyped, which
    makes those dimensions tautological here - they were separately confirmed
    against a live dump. Mounts, storages, cwd, devices and paths, where every
    correction landed, are the measured literals below.
    """

    pol = open(pol_path).read()

    def strset(name):
        m = re.search(r'^%s := \{(.*?)^\}' % re.escape(name), pol, re.S | re.M)
        if not m:
            sys.exit("FATAL: cannot find set %s" % name)
        vals = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
        return [v.encode().decode('unicode_escape') for v in vals]

    def first_image():
        m = re.search(r'^allowed_images := \[(.*?)^\]', pol, re.S | re.M)
        return re.findall(r'"([^"]+)"', m.group(1))[0]

    IMG   = first_image()
    PAUSE = re.search(r'^pause_image := "([^"]+)"', pol, re.M).group(1)
    ENV   = strset('workload_env')
    WCAPS = strset('workload_caps')
    PCAPS = strset('pause_caps')
    MASK  = strset('masked_paths')
    ROPATH= strset('readonly_paths')

    if any('RUN splice-env.sh' in e for e in ENV):
        sys.exit("FATAL: workload_env is still the placeholder. Run:\n"
                 "  ./gen-workload-env.sh workload-prod.yaml > workload_env.rego\n"
                 "  ./splice-env.sh prod-policy.rego workload_env.rego")

    # Platform env the orchestrator injects: 9 entries, matching
    # platform_env_patterns. No TERM, because Terminal is false.
    PLATFORM = [
        "HOSTNAME=cvn-engine-glm53",
        "KUBERNETES_SERVICE_HOST=10.96.0.1",
        "KUBERNETES_SERVICE_PORT=443",
        "KUBERNETES_SERVICE_PORT_HTTPS=443",
        "KUBERNETES_PORT=tcp://10.96.0.1:443",
        "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
        "KUBERNETES_PORT_443_TCP_PROTO=tcp",
        "KUBERNETES_PORT_443_TCP_PORT=443",
        "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
    ]

    # Measured 5 Nov from the kata journal. The 16 hex chars are per FILE, not per
    # boot or per container: these four values recurred across two boots. Using one
    # shared value here is what let a wrong source pattern pass the fixture while
    # the agent refused it -- the fixture agreed with the policy and both were
    # wrong. Keep these distinct.
    SUF = {"hosts":           "3ac2f4628ee9533e",
           "termination-log": "b8185aa0f8f15616",
           "hostname":        "c00d24d722dd603c",
           "resolv.conf":     "e55d997e8dac7257"}

    # The workload's container_id is the 64-hex containerd id, NOT the container
    # name. `kubectl describe` renders it as the name and is not to be trusted for
    # this field; read the kata journal.
    WCID  = "ae96bad392d4af452d8b58cd2a51780091a66b6c4eebfaef59c3b6732c80164b"
    PSUF  = "e03e879aade61248"           # pause's own 16-hex, matches [a-z0-9]{16}
    SBXID = "a" * 64                     # pause container_id is the sandbox id
    SHARED = "/run/kata-containers/shared/containers"
    WSTORE = "/run/kata-containers/sandbox/storage/MDow"   # base64 of "0:0"

    def mount(dest, t, src, opts):
        return {"destination": dest, "type_": t, "source": src, "options": opts}

    # Measured workload mount table, 12 rows.
    WMOUNTS = [
        mount("/proc", "proc", "proc", ["nosuid", "noexec", "nodev"]),
        mount("/dev", "tmpfs", "tmpfs", ["nosuid", "strictatime", "mode=755", "size=65536k"]),
        mount("/dev/pts", "devpts", "devpts",
              ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]),
        mount("/dev/shm", "bind", "/run/kata-containers/sandbox/shm", ["rbind"]),
        mount("/dev/mqueue", "mqueue", "mqueue", ["nosuid", "noexec", "nodev"]),
        mount("/sys", "sysfs", "sysfs", ["nosuid", "noexec", "nodev", "rw"]),
        mount("/sys/fs/cgroup", "cgroup", "cgroup",
              ["nosuid", "noexec", "nodev", "relatime", "rw"]),
        mount("/weights", "bind", WSTORE, ["rbind", "rprivate", "ro"]),
        mount("/etc/hosts", "bind", "%s/%s-%s-hosts" % (SHARED, WCID, SUF["hosts"]),
              ["rbind", "rprivate", "rw"]),
        mount("/etc/hostname", "bind", "%s/%s-%s-hostname" % (SHARED, WCID, SUF["hostname"]),
              ["rbind", "rprivate", "rw"]),
        mount("/etc/resolv.conf", "bind", "%s/%s-%s-resolv.conf" % (SHARED, WCID, SUF["resolv.conf"]),
              ["rbind", "rprivate", "rw"]),
        mount("/dev/termination-log", "bind",
              "%s/%s-%s-termination-log" % (SHARED, WCID, SUF["termination-log"]),
              ["rbind", "rprivate", "rw"]),
    ]

    # Measured pause mount table, 7 rows. /sys is rw here too.
    PMOUNTS = [
        mount("/proc", "proc", "proc", ["nosuid", "noexec", "nodev"]),
        mount("/dev", "tmpfs", "tmpfs", ["nosuid", "strictatime", "mode=755", "size=65536k"]),
        mount("/dev/pts", "devpts", "devpts",
              ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]),
        mount("/dev/mqueue", "mqueue", "mqueue", ["nosuid", "noexec", "nodev"]),
        mount("/sys", "sysfs", "sysfs", ["nosuid", "noexec", "nodev", "rw"]),
        mount("/dev/shm", "bind", "/run/kata-containers/sandbox/shm", ["rbind"]),
        mount("/etc/resolv.conf", "bind", "%s/%s-%s-resolv.conf" % (SHARED, SBXID, PSUF),
              ["rbind", "ro", "nosuid", "nodev", "noexec"]),
    ]

    def caps(c):
        return {"Bounding": c, "Effective": c, "Permitted": c,
                "Ambient": [], "Inheritable": []}

    def rootfs_storage(cid, src, img_key, img_val):
        return {
            "driver": "image_guest_pull", "fstype": "overlay",
            "mount_point": "/run/kata-containers/%s/rootfs" % cid,
            "source": src, "options": [], "shared": False, "fs_group": None,
            "driver_options": ["image_guest_pull=" + json.dumps(
                {img_key: img_val, "io.kubernetes.cri.container-type": "x"},
                separators=(",", ":"))],
        }

    workload = {
        "container_id": WCID,
        "devices": [],
        "sandbox_pidns": False,
        "storages": [
            rootfs_storage(WCID, IMG, "io.kubernetes.cri.image-name", IMG),
            {"driver": "scsi", "fstype": "ext4", "mount_point": WSTORE,
             "source": "0:0", "options": [], "shared": False, "fs_group": None,
             "driver_options": []},
        ],
        "OCI": {
            "Annotations": {"io.kubernetes.cri.container-type": "container",
                            "io.kubernetes.cri.image-name": IMG},
            "Hooks": None,
            "Root": {"Path": "/run/kata-containers/%s/rootfs" % WCID, "Readonly": False},
            "Mounts": WMOUNTS,
            "Linux": {"Devices": [], "MaskedPaths": [], "ReadonlyPaths": [],
                      "Sysctl": {}, "Seccomp": None},
            "Process": {
                "Args": ["/opt/cvn/entrypoint.sh"],
                "Cwd": "/sgl-workspace/sglang",
                "User": {"UID": 0, "GID": 0},
                "NoNewPrivileges": False, "Terminal": False, "Rlimits": [],
                "Env": ENV + PLATFORM, "Capabilities": caps(WCAPS),
            },
        },
    }

    pause = {
        "container_id": SBXID,
        "devices": [],
        "sandbox_pidns": False,
        "storages": [rootfs_storage(SBXID, "pause",
                                    "io.kubernetes.cri.podsandbox.image-name", PAUSE)],
        "OCI": {
            "Annotations": {"io.kubernetes.cri.container-type": "sandbox",
                            "io.kubernetes.cri.podsandbox.image-name": PAUSE},
            "Hooks": None,
            "Root": {"Path": "/run/kata-containers/%s/rootfs" % SBXID, "Readonly": True},
            "Mounts": PMOUNTS,
            "Linux": {"Devices": [], "MaskedPaths": MASK, "ReadonlyPaths": ROPATH,
                      "Sysctl": {"net.ipv4.ip_unprivileged_port_start": "0",
                                 "net.ipv4.ping_group_range": "0 2147483647"},
                      "Seccomp": None},
            "Process": {
                "Args": ["/pause"], "Cwd": "/",
                "User": {"UID": 65535, "GID": 65535},
                "NoNewPrivileges": True, "Terminal": False, "Rlimits": [],
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "Capabilities": caps(PCAPS),
            },
        },
    }

    sandbox = {
        "guest_hook_path": "",
        "kernel_modules": [],
        "sandbox_pidns": False,
        "storages": [
            {"driver": "ephemeral", "fstype": "tmpfs",
             "mount_point": "/run/kata-containers/sandbox/shm",
             "source": "shm",
             "options": ["noexec", "nosuid", "nodev", "mode=1777", "size=67108864"],
             "shared": False, "fs_group": None, "driver_options": []},
        ],
    }

    out = {"workload": workload, "pause": pause, "sandbox": sandbox}
    for name, obj in out.items():
        with open(os.path.join(outdir, "fixture-%s.json" % name), "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")

    print("   workload fixture: %d env entries (%d pinned + %d platform), "
          "%d mounts, %d storages, %d caps"
          % (len(ENV) + len(PLATFORM), len(ENV), len(PLATFORM),
             len(WMOUNTS), len(workload["storages"]), len(WCAPS)))
    print("   pause fixture:    %d mounts, %d caps, %d masked, %d readonly"
          % (len(PMOUNTS), len(PCAPS), len(MASK), len(ROPATH)))
    print("   image pinned:     %s" % IMG)
    return out


POL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'prod-policy.rego')
TMP = tempfile.mkdtemp(prefix='polتest-' if False else 'poltest-')
RULE_C, RULE_S = 'CreateContainerRequest', 'CreateSandboxRequest'


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def opa_eval(policy, obj, rule):
    p = os.path.join(TMP, 'in.json')
    with open(p, 'w') as f:
        json.dump(obj, f)
    r = run(['opa', 'eval', '-f', 'raw', '-d', policy, '-i', p,
             'data.agent_policy.' + rule])
    out = (r.stdout or '').strip()
    if out in ('true', 'false'):
        return out == 'true'
    return 'ERROR: ' + (out or r.stderr.strip())[:200]


# ---------------------------------------------------------------- fixtures
if not shutil.which('opa'):
    sys.exit('FATAL: opa not on PATH')
BASE = build_fixtures(POL, TMP)
RULE = {'workload': RULE_C, 'pause': RULE_C, 'sandbox': RULE_S}

# ---------------------------------------------------------------- helpers
def proc(f):   return f['OCI']['Process']
def linux(f):  return f['OCI']['Linux']
def mounts(f): return f['OCI']['Mounts']

def find_mount(f, dest):
    for m in mounts(f):
        if m['destination'] == dest:
            return m
    raise AssertionError('fixture has no mount at ' + dest)

def find_env(f, prefix):
    for i, e in enumerate(proc(f)['Env']):
        if e.startswith(prefix):
            return i
    raise AssertionError('fixture has no env entry ' + prefix)

def rootfs_storage(f):
    for s in f['storages']:
        if s['driver'] == 'image_guest_pull':
            return s
    raise AssertionError('fixture has no image_guest_pull storage')

def scsi_storage(f):
    for s in f['storages']:
        if s['driver'] == 'scsi':
            return s
    raise AssertionError('fixture has no scsi storage')

# ---------------------------------------------------------------- cases
# (name, fixture, mutation). Each mutation edits a deep copy in place.
CASES = [
 # --- image and rootfs binding -------------------------------------------
 ('image digest swapped in storage source', 'workload',
  lambda f: rootfs_storage(f).__setitem__('source',
      re.sub(r'@sha256:[0-9a-f]{64}', '@sha256:' + 'de'*32, rootfs_storage(f)['source']))),
 ('driver_options image-name disagrees with storage source', 'workload',
  lambda f: rootfs_storage(f).__setitem__('driver_options',
      [re.sub(r'(?<=cri\.image-name":")[^"]+',
              'docker.io/attacker/evil@sha256:' + 'ab'*32,
              rootfs_storage(f)['driver_options'][0])])),
 ('image-name JSON smuggled into a non-image-pull driver option', 'workload',
  lambda f: rootfs_storage(f).__setitem__('driver_options',
      ['unrelated_opt=' + rootfs_storage(f)['driver_options'][0].split('=', 1)[1]])),
 ('driver_options image-name key removed', 'workload',
  lambda f: rootfs_storage(f).__setitem__('driver_options', ['image_guest_pull={}'])),
 ('driver_options loses the image_guest_pull= prefix', 'workload',
  lambda f: rootfs_storage(f).__setitem__('driver_options',
      [rootfs_storage(f)['driver_options'][0].replace('image_guest_pull=', '', 1)])),
 ('Root.Path not the expected rootfs', 'workload',
  lambda f: f['OCI']['Root'].__setitem__('Path', '/run/kata-containers/other/rootfs')),
 ('rootfs storage mount_point disagrees with Root.Path', 'workload',
  lambda f: rootfs_storage(f).__setitem__('mount_point',
      '/run/kata-containers/other/rootfs')),
 ('second image_guest_pull storage added', 'workload',
  lambda f: f['storages'].append(copy.deepcopy(rootfs_storage(f)))),
 ('rootfs fstype not overlay', 'workload',
  lambda f: rootfs_storage(f).__setitem__('fstype', 'ext4')),
 ('rootfs storage shared', 'workload',
  lambda f: rootfs_storage(f).__setitem__('shared', True)),
 ('rootfs storage fs_group set', 'workload',
  lambda f: rootfs_storage(f).__setitem__('fs_group', {'group_id': 0})),
 ('rootfs storage carries mount options', 'workload',
  lambda f: rootfs_storage(f).__setitem__('options', ['rw'])),

 # --- environment ---------------------------------------------------------
 ('extra env var added', 'workload',
  lambda f: proc(f)['Env'].append('CVN_BACKDOOR=1')),
 ('pinned env var removed', 'workload',
  lambda f: proc(f)['Env'].pop(find_env(f, 'PATH='))),
 ('pinned env value altered', 'workload',
  lambda f: proc(f)['Env'].__setitem__(find_env(f, 'PATH='), 'PATH=/tmp')),
 ('LD_PRELOAD injected', 'workload',
  lambda f: proc(f)['Env'].append('LD_PRELOAD=/tmp/evil.so')),
 ('LD_LIBRARY_PATH altered from the pinned value', 'workload',
  lambda f: proc(f)['Env'].__setitem__(find_env(f, 'LD_LIBRARY_PATH='),
      'LD_LIBRARY_PATH=/tmp/lib')),
 ('PYTHONPATH injected', 'workload',
  lambda f: proc(f)['Env'].append('PYTHONPATH=/tmp')),
 ('byte-identical env entry duplicated', 'workload',
  lambda f: proc(f)['Env'].append(proc(f)['Env'][find_env(f, 'PATH=')])),
 # env_keys_sane is falsifiable by duplicating a PLATFORM key with a second
 # legal value: both entries pass env_allowed via env_platform, the two strings
 # differ so the repeated-entry check is satisfied, and every pinned entry is
 # still present - so env_keys_sane is the ONLY rule that can refuse this.
 ('platform key duplicated with a second legal value', 'workload',
  lambda f: proc(f)['Env'].append('KUBERNETES_SERVICE_PORT=8443')),
 ('HOSTNAME platform var with illegal shape', 'workload',
  lambda f: proc(f)['Env'].__setitem__(find_env(f, 'HOSTNAME='),
      'HOSTNAME=../../etc/passwd')),
 ('KUBERNETES_SERVICE_HOST set to a name, not an address', 'workload',
  lambda f: proc(f)['Env'].__setitem__(find_env(f, 'KUBERNETES_SERVICE_HOST='),
      'KUBERNETES_SERVICE_HOST=evil.example.com')),

 # --- process -------------------------------------------------------------
 ('entrypoint replaced with a shell', 'workload',
  lambda f: proc(f).__setitem__('Args', ['/bin/sh', '-c', 'id'])),
 ('argument appended to the entrypoint', 'workload',
  lambda f: proc(f)['Args'].append('--trust-remote-code')),
 ('Cwd changed', 'workload',
  lambda f: proc(f).__setitem__('Cwd', '/')),
 # NOTE: workload_caps is the COMPLETE 41-capability set, because the
 # container is privileged. There is no capability outside it, so "a capability
 # was added" cannot be expressed as a mutation and is not a gap when it
 # admits. caps_exact pins the fact of full privilege; it does not restrain it.
 # Say that plainly to the Trusted Router rather than implying the cap list is
 # a restriction.
 ('capability removed', 'workload',
  lambda f: proc(f)['Capabilities']['Bounding'].pop()),
 ('capability replaced with an unknown name', 'workload',
  lambda f: proc(f)['Capabilities']['Bounding'].__setitem__(0, 'CAP_NOT_A_REAL_CAP')),
 ('ambient capabilities non-empty', 'workload',
  lambda f: proc(f)['Capabilities'].__setitem__('Ambient', ['CAP_CHOWN'])),
 ('inheritable capabilities non-empty', 'workload',
  lambda f: proc(f)['Capabilities'].__setitem__('Inheritable', ['CAP_CHOWN'])),
 ('effective caps reduced below bounding', 'workload',
  lambda f: proc(f)['Capabilities']['Effective'].pop()),
 ('Rlimits non-empty', 'workload',
  lambda f: proc(f).__setitem__('Rlimits',
      [{'type': 'RLIMIT_NOFILE', 'hard': 1024, 'soft': 1024}])),
 ('Terminal true', 'workload',
  lambda f: proc(f).__setitem__('Terminal', True)),
 ('pause UID no longer 65535', 'pause',
  lambda f: proc(f)['User'].__setitem__('UID', 0)),
 ('pause NoNewPrivileges disabled', 'pause',
  lambda f: proc(f).__setitem__('NoNewPrivileges', False)),
 ('pause rootfs writable', 'pause',
  lambda f: f['OCI']['Root'].__setitem__('Readonly', False)),
 ('pause image changed in driver_options', 'pause',
  lambda f: rootfs_storage(f).__setitem__('driver_options',
      [rootfs_storage(f)['driver_options'][0].replace('pause:3.10.1', 'pause:3.9')])),
 ('pause storage source changed', 'pause',
  lambda f: rootfs_storage(f).__setitem__('source', 'notpause')),

 # --- mounts --------------------------------------------------------------
 ('WEIGHTS MOUNTED READ-WRITE', 'workload',
  lambda f: find_mount(f, '/weights').__setitem__('options',
      ['rbind', 'rprivate', 'rw'])),
 ('extra mount added', 'workload',
  lambda f: mounts(f).append({'destination': '/mnt/extra', 'type_': 'bind',
      'source': '/run/kata-containers/sandbox/storage/MDow',
      'options': ['rbind', 'rw']})),
 ('mount removed', 'workload',
  lambda f: mounts(f).pop(0)),
 ('mount over /usr', 'workload',
  lambda f: find_mount(f, '/weights').__setitem__('destination', '/usr/lib')),
 ('mount over /opt/cvn', 'workload',
  lambda f: find_mount(f, '/weights').__setitem__('destination', '/opt/cvn')),
 ('mount source with a parent-directory escape', 'workload',
  lambda f: find_mount(f, '/weights').__setitem__('source',
      '/run/kata-containers/sandbox/storage/../../../../etc')),
 ('duplicate mount destination', 'workload',
  lambda f: mounts(f).append(copy.deepcopy(find_mount(f, '/weights')))),
 ('cgroup mount options changed', 'workload',
  lambda f: find_mount(f, '/sys/fs/cgroup').__setitem__('options',
      ['nosuid', 'noexec', 'nodev', 'relatime', 'rw', 'nsdelegate'])),
 ('/sys remounted suid', 'workload',
  lambda f: find_mount(f, '/sys').__setitem__('options', ['noexec', 'nodev', 'rw'])),
 ('shared-file suffix not 16 hex', 'workload',
  lambda f: find_mount(f, '/etc/hosts').__setitem__('source',
      find_mount(f, '/etc/hosts')['source'].replace('-hosts', 'X-hosts'))),
 ('shared-file suffix uppercase', 'workload',
  lambda f: find_mount(f, '/etc/hosts').__setitem__('source',
      re.sub(r'-[0-9a-f]{16}-hosts$', '-3AC2F4628EE9533E-hosts',
             find_mount(f, '/etc/hosts')['source']))),
 # The point of binding shared_re() to the request's own container_id: a mount
 # may not reference ANOTHER container's shared files, even a well-formed one.
 ('shared path points at another container id', 'workload',
  lambda f: find_mount(f, '/etc/hosts').__setitem__('source',
      find_mount(f, '/etc/hosts')['source'].replace(f['container_id'], 'f' * 64))),
 # cid_sane. Not isolated: changing container_id also breaks expected_rootfs,
 # so this denies twice over. Kept because a metacharacter reaching the regex
 # is the one way shared_re() could be widened.
 ('container_id carrying a regex metacharacter', 'workload',
  lambda f: f.__setitem__('container_id', 'a.' * 32)),
 ('mount type spelling swapped to the wrong field', 'workload',
  lambda f: (mounts(f)[0].pop('type_'), mounts(f)[0].__setitem__('type', 'nfs'))),

 # --- devices, hooks, seccomp --------------------------------------------
 ('OCI device added', 'workload',
  lambda f: linux(f).__setitem__('Devices',
      [{'path': '/dev/mem', 'type': 'c', 'major': 1, 'minor': 1}])),
 ('agent device added', 'workload',
  lambda f: f.__setitem__('devices',
      [{'container_path': '/dev/mem', 'type': 'c', 'major': 1, 'minor': 1}])),
 ('lifecycle hook added', 'workload',
  lambda f: f['OCI'].__setitem__('Hooks',
      {'Prestart': [{'Path': '/bin/sh', 'Args': ['-c', 'curl evil']}]})),
 ('seccomp profile supplied', 'workload',
  lambda f: linux(f).__setitem__('Seccomp', {'DefaultAction': 'SCMP_ACT_ALLOW'})),
 ('pause masked path removed', 'pause',
  lambda f: linux(f)['MaskedPaths'].pop()),
 ('pause readonly path removed', 'pause',
  lambda f: linux(f)['ReadonlyPaths'].pop()),
 ('pause sysctl added', 'pause',
  lambda f: linux(f)['Sysctl'].__setitem__('kernel.shmmax', '999')),

 # --- storages ------------------------------------------------------------
 ('weights storage carries options', 'workload',
  lambda f: scsi_storage(f).__setitem__('options', ['rw'])),
 ('weights storage source not a scsi address', 'workload',
  lambda f: scsi_storage(f).__setitem__('source', '/dev/nvme1n1')),
 ('weights storage mount_point outside sandbox storage', 'workload',
  lambda f: scsi_storage(f).__setitem__('mount_point', '/weights')),
 ('weights storage fstype changed', 'workload',
  lambda f: scsi_storage(f).__setitem__('fstype', 'overlay')),
 ('unknown storage driver added', 'workload',
  lambda f: f['storages'].append({'driver': 'local', 'fstype': 'ext4',
      'mount_point': '/run/kata-containers/sandbox/storage/ZZZZ',
      'source': '0:1', 'options': [], 'shared': False, 'fs_group': None,
      'driver_options': []})),
 ('sandbox_pidns enabled', 'workload',
  lambda f: f.__setitem__('sandbox_pidns', True)),

 # --- sandbox request -----------------------------------------------------
 ('guest hook path set', 'sandbox',
  lambda f: f.__setitem__('guest_hook_path', '/opt/hooks')),
 ('kernel module requested', 'sandbox',
  lambda f: f.__setitem__('kernel_modules', ['evil'])),
 ('extra sandbox storage', 'sandbox',
  lambda f: f['storages'].append({'driver': 'ephemeral', 'fstype': 'tmpfs',
      'mount_point': '/run/kata-containers/sandbox/extra', 'source': 'shm',
      'options': [], 'shared': False, 'fs_group': None, 'driver_options': []})),
 ('sandbox shm size widened', 'sandbox',
  lambda f: f['storages'][0].__setitem__('options',
      ['noexec', 'nosuid', 'nodev', 'mode=1777', 'size=1073741824'])),
 ('sandbox shm exec-able', 'sandbox',
  lambda f: f['storages'][0].__setitem__('options',
      ['nosuid', 'nodev', 'mode=1777', 'size=67108864'])),
]

# Policy mutations: each deliberate exception must be load-bearing. If the
# policy still ADMITS with an exception removed, that exception is widening
# the policy for nothing and should be deleted.
POLICY_CASES = [
 ('LD_LIBRARY_PATH exception is load-bearing', 'workload',
  lambda s: re.sub(r'forbidden_env_exception_prefixes := \[[^\]]*\]',
                   'forbidden_env_exception_prefixes := ["ZZZ_NO_SUCH_PREFIX="]', s)),
]

# ---------------------------------------------------------------- run
print('policy: %s' % POL)
print('\n== phase 0: a correct request must be ADMITTED ==')
print('   (if any of these DENY, every negative result below is meaningless)')
abort = False
for name in ('workload', 'pause', 'sandbox'):
    got = opa_eval(POL, BASE[name], RULE[name])
    ok = got is True
    print('   %-10s %-24s %s' % (name, RULE[name], 'ADMIT' if ok else 'DENY  <-- %s' % got))
    abort |= not ok
if abort:
    sys.exit('\nABORT: a baseline does not admit. Fix that before reading the suite.')

print('\n== phase 1+2: %d mutations must each DENY ==' % len(CASES))
passed = failed = errored = 0
for name, base, mut in CASES:
    f = copy.deepcopy(BASE[base])
    before = json.dumps(f, sort_keys=True)
    try:
        mut(f)
    except AssertionError as e:
        print('   ERROR  %-52s %s' % (name[:52], e)); errored += 1; continue
    # A mutation that leaves the fixture byte-identical tests nothing, and the
    # resulting ADMIT would otherwise be reported as a policy gap. Two stale
    # str.replace() targets did exactly that on 5 Nov after the shared-path
    # scheme was corrected: both searched for text that no longer existed.
    if json.dumps(f, sort_keys=True) == before:
        print('   NO-OP     %-50s <-- TEST BUG, mutation changed nothing' % name[:50])
        errored += 1; continue
    got = opa_eval(POL, f, RULE[base])
    if got is False:
        passed += 1
    elif got is True:
        print('   ADMITTED  %-50s <-- POLICY GAP' % name[:50]); failed += 1
    else:
        print('   ERROR     %-50s %s' % (name[:50], got)); errored += 1

print('\n== phase 3: %d exceptions must be load-bearing ==' % len(POLICY_CASES))
src = open(POL).read()
for name, base, pmut in POLICY_CASES:
    mutated = pmut(src)
    if mutated == src:
        print('   ERROR     %-50s mutation did not apply' % name[:50]); errored += 1; continue
    p2 = os.path.join(TMP, 'mut.rego')
    open(p2, 'w').write(mutated)
    got = opa_eval(p2, BASE[base], RULE[base])
    if got is False:
        print('   OK        %s' % name); passed += 1
    elif got is True:
        print('   STILL ADMITS  %-46s <-- exception is dead, delete it' % name[:46]); failed += 1
    else:
        print('   ERROR     %-50s %s' % (name[:50], got)); errored += 1

total = len(CASES) + len(POLICY_CASES)
print('\n%d/%d denied as required, %d gaps, %d errors' % (passed, total, failed, errored))
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if (failed or errored) else 0)
