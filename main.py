#!/usr/bin/env python3

import os
import subprocess
import tempfile
import logging
import re
import yaml
from slugify import slugify
import argparse

def lerp(x0, x1, /, t):
    return x0*(1-t) + x1*t

def ensure_dir(path):
    try:
        os.makedirs(path)
        logging.info(f"made dirs up to {path}")
    except FileExistsError:
        logging.info(f"using existing {path}")

def get_compose_file(dir):
    for file in os.scandir(dir):
        if file.is_file() and re.match("docker-compose\.ya?ml", file.name):
            logging.info(f"found {file.path}")
            return file
    else:
        return None

def convert_service(name, service, pvc_name_template="{{{{ .Release.Name }}}}-{name}", ignore_volumes=[]):
    container = {}
    volumes = {}
    extras = []

    container['name'] = name
    container['image'] = service['image']
    if 'environment' in service:
        container['env'] = service['environment']
    
    for vol_mount in service.get('volumes', []):
        # example: vol_mount = '/data/honeypots/log:/var/log/honeypots'
        if 'volumeMounts' not in container:
            container['volumeMounts'] = []
        
        host_path, guest_path = vol_mount.split(":")
        pvc_name, pvc_path = host_path.removeprefix("/").split("/", 1)
        pvc_name = slugify(pvc_name)
        vol_name = pvc_name

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
        
        if vol_name not in ignore_volumes:
            extras.append({
                'apiVersion': "v1",
                'kind': "PersistentVolumeClaim",
                'metadata': {
                    'name': pvc_name_template.format(name=pvc_name),
                    'namespace': "{{ .Release.Namespace }}",
                    'labels' : {
                        'app': "{{ .Release.Namespace }}"
                    }
                },
                'spec': {
                    'accessModes': ['ReadWriteOnce'],
                    'resources': {
                        'requests': {
                            'storage': '100Mi'
                        }
                    }
                }
            })
    
    for tmpfs_mount in service.get('tmpfs', []):
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
    
    return container, volumes, extras
 
def main():
    parser = argparse.ArgumentParser(description="Generate templates from tpot configurations.")
    parser.add_argument('-r', '--repo', type=str, help="Git repository URL to clone from.", default="https://github.com/telekom-security/tpotce.git")
    parser.add_argument('-b', '--branch', type=str, help="Git branch to clone.", default="master")
    parser.add_argument('-p', '--path', type=str, help="Source path within git repo to search for services.", default="docker")
    parser.add_argument('-d', '--dest', type=str, help="Destination directory to write templates to.", default="./out")
    parser.add_argument('-x', '--exclude', action='extend', nargs='+', type=str, help="Don't generate based on these directories in the git repo; can specify multiple times.", default=[])
    parser.add_argument('-m', '--mount', action='extend', nargs='+', type=str, help="Don't create PVCs for these mounts; can specify multiple times.", default=[])

    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()

    logging.basicConfig(level=max(lerp(logging.WARN, logging.INFO, args.verbose), logging.DEBUG))
    logging.debug(f'{args}')

    if args.exclude:
        exclude = parser.exclude
    else:
        exclude = ['p0f', 'fatt', 'suricata', 'elk', 'ewsposter', 'nginx', 'spiderfoot', 'deprecated']
        logging.info(f"defaulting {exclude=}")
    
    if args.mount:
        mount = parser.mount
    else:
        mount = ['data']
        logging.info(f"defaulting {mount=}")
    
    out_dir = args.dest
    ensure_dir(out_dir)

    gitignore_file = os.path.join(out_dir, ".gitignore")

    src_repo = args.repo
    src_branch = args.branch
    repo_url_guess = src_repo.removesuffix(".git") + "/tree/" + src_branch
    repo_name_guess = src_repo.removesuffix(".git").removesuffix("/").split("/")[-1]

    with open(gitignore_file, 'w') as stream:
        pass # truncate file to zero length

    with tempfile.TemporaryDirectory(prefix=repo_name_guess + "-") as temp_dir:
        logging.info(f"cloning {src_repo}:{src_branch} into {temp_dir}")
        subprocess.run(["git", "clone", "-b", src_branch, "--depth", "1", src_repo, temp_dir])

        search_dir = os.path.join(temp_dir, args.path)
        
        for container_dir in os.scandir(search_dir):
            if not container_dir.is_dir() or container_dir.name in exclude:
                logging.info(f"skipping {container_dir.path}")
                continue
            logging.info(f"scanning {container_dir.path}")

            compose_file = get_compose_file(container_dir)
            out_fname = "_" + container_dir.name + ".tpl"
            out_file = os.path.join(out_dir, out_fname)

            logging.debug(f"writing {out_file}")
            with open(out_file, 'w') as stream: # insert source citation
                stream.write('{{/* derived from ' + repo_url_guess + '/' + os.path.relpath(compose_file, temp_dir) + ' */}}\n')
            
            logging.debug(f"appending {gitignore_file}")
            with open(gitignore_file, 'a') as stream: # add generated files to .gitignore
                stream.writelines([out_fname, "\n"])

            logging.debug(f"reading {compose_file.path}")
            with open(compose_file, 'r') as stream:
                contents = yaml.safe_load(stream)
            
            services = contents.get('services',{})

            for service_name, service in services.items():
                service_name = slugify(service_name)
                container, volumes, extras = convert_service(service_name, service, ignore_volumes=mount)

                with open(out_file, 'a') as stream:
                    stream.writelines([
                        '{{/* container spec and volumes for ' + service_name + ' */}}\n',
                        '{{- define "' + service_name + '.containers" }}\n',
                        f'## Source: {out_fname}\n',
                    ])
                    yaml.safe_dump([container], stream)
                    stream.writelines([
                        '{{- end }}\n',
                        '{{- define "' + service_name + '.volumes" }}\n',
                        f'## Source: {out_fname}\n',
                    ])
                    if volumes:
                        yaml.safe_dump(list(volumes.values()), stream)
                    stream.writelines([
                        '{{- end }}\n',
                        '{{- define "' + service_name + '.extras" }}\n',
                        f'## Source: {out_fname}\n',
                    ])
                    yaml.safe_dump_all(extras, stream)
                    stream.writelines([
                        '{{- end }}\n',
                    ])
if __name__ == "__main__":
    main()

        


    


        

