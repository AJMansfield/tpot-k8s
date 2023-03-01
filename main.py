#!/usr/bin/env python3

import os
import subprocess
import tempfile
import logging
import re
import yaml
from slugify import slugify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

def ensure_dir(path):
    try:
        os.makedirs(path)
        logger.info(f"made dirs up to {path}")
    except FileExistsError:
        logger.info(f"using existing {path}")

src_repo = "https://github.com/telekom-security/tpotce.git"
src_branch = "master"
repo_url = src_repo.removesuffix(".git") + "/tree/" + src_branch

pvc_name_template = "{{{{ .Release.Name }}}}-{name}"

build_dir = os.path.join(os.path.dirname(__file__), "build")
ensure_dir(build_dir)

if False:
    temp_directory = tempfile.TemporaryDirectory(dir=build_dir)
    temp_dir = temp_directory.name
    temp_directory.__enter__()
else:
    temp_dir = os.path.join(build_dir, "temp")
    ensure_dir(temp_dir)

out_dir = os.path.join(build_dir, "out")
ensure_dir(out_dir)

git_dir = os.path.join(temp_dir, "tpotce")

logger.info(f"cloning {src_repo}:{src_branch}")
subprocess.run(["git", "clone", "-b", src_branch, "--depth", "1", src_repo, git_dir], cwd=temp_dir)

dock_dir = os.path.join(git_dir, "docker")

def get_compose_file(dir):
    for file in os.scandir(dir):
        if file.is_file() and re.match("docker-compose\.ya?ml", file.name):
            return file
    else:
        return None

def convert_service(name, svc):
    container = {}
    volumes = {}

    container['name'] = name
    container['image'] = svc['image']
    if 'environment' in svc:
        container['env'] = svc['environment']
    
    for vol_mount in svc.get('volumes', []):
        # example: vol_mount = '/data/honeypots/log:/var/log/honeypots'
        if 'volumeMounts' not in container:
            container['volumeMounts'] = []
        
        host_path, guest_path = vol_mount.split(":")
        pvc_name, pvc_path = host_path.removeprefix("/").split("/", 1)
        vol_name = slugify(pvc_name)

        volumes[vol_name] = {
            'name': vol_name,
            'persistentVolumeClaim': {
                'claimName': pvc_name_template.format(name=pvc_name),
            }}
        
        container['volumeMounts'].append({
            'name': vol_name,
            'subPath': pvc_path,
            'mountPath': guest_path,
            })
    
    for tmpfs_mount in svc.get('tmpfs', []):
        # example: tmpfs_mount = '/tmp/conpot:uid=2000,gid=2000'
        if 'volumeMounts' not in container:
            container['volumeMounts'] = []
        
        guest_path, attrs = tmpfs_mount.split(":")
        attrs = dict(map(lambda a: a.split("="), attrs.split(",")))
        vol_name = slugify(name + '-' + guest_path.removeprefix("/"))

        securityContext = {}
        if 'uid' in attrs:
            securityContext['runAsUser'] = int(attrs['uid'])
        if 'gid' in attrs:
            securityContext['runAsGroup'] = int(attrs['gid'])
            securityContext['fsGroup'] = int(attrs['gid'])
        if securityContext:
            container['securityContext'] = securityContext
        
        volumes[vol_name] = {
            'name': vol_name,
            'emptyDir': {
                'medium': 'Memory',
            }}
        
        container['volumeMounts'].append({
            'name': vol_name,
            'mountPath': guest_path,
            })
    
    return container, volumes
        
exclude_dirs = [
    'p0f', 'fatt', 'suricata', 'elk', 'ewsposter', 'nginx', 'spiderfoot', 'deprecated'
]
for container_dir in os.scandir(dock_dir):
    if not container_dir.is_dir() or container_dir.name in exclude_dirs:
        logger.info(f"skipping {container_dir.path}")
        continue
    logger.info(f"scanning {container_dir.path}")

    compose_file = get_compose_file(container_dir)
    out_file = os.path.join(out_dir, "_" + container_dir.name + ".tpl")

    logger.info(f"reading {compose_file.path}")
    logger.info(f"writing {out_file}")
    with open(out_file, 'w') as stream:
        stream.write('{{/* derived from ' + repo_url + "/" + os.path.relpath(compose_file, git_dir) + ' */}}\n')

    with open(compose_file, "r") as stream:
        contents = yaml.safe_load(stream)
    
    services = contents.get('services',{})
    
    for service_name, service in services.items():
        service_name = slugify(service_name)
        container, volumes = convert_service(service_name, service)

        with open(out_file, 'a') as stream:
            stream.write('{{/* container spec and volumes for ' + service_name + ' */}}\n')
            
            stream.write('{{- define "' + service_name + '.containers" }}\n')
            yaml.safe_dump([container], stream)
            stream.write('{{- end }}\n')
            stream.write('{{- define "' + service_name + '.volumes" }}\n')
            yaml.safe_dump(list(volumes.values()), stream)
            stream.write('{{- end }}\n')
            stream.write('{{- define "' + service_name + '.extras" }}\n')
            stream.write('{{- end }}\n')

        

