import ssh


def ssh_connect(ip='', port=0, username='', passwd=''):
    sshclient = ssh.SSHClient()
    sshclient.set_missing_host_key_policy(ssh.AutoAddPolicy())
    try:
        sshclient.connect(ip, port, username, passwd)
        return sshclient
    except Exception, e:
        raise e


def get_file_list(sshclient=None, path=''):
    _, stdout, _ = sshclient.exec_command('ls -p ' + path)
    file_info_list = stdout.read().split('\n')
    result_dict = []
    for file_name in file_info_list:
        fileinfo = {}
        fileinfo['filename'] = file_name
        result_dict.append(fileinfo)
    return result_dict


def create_file_onssh(sshclient=None, exec_path='', filepath=''):
    _, stdout, _ = sshclient.exec_command("echo 'path="+'"' + exec_path + '"' + "' > " + filepath)
    _, stdout, _ = sshclient.exec_command('readelf --debug-dump=decodedline ' + exec_path + ' > ' + '/tmp/antman_pin_map')
    _, stdout, _ = sshclient.exec_command('readelf -h --debug-dump=decodedline ' + exec_path + ' | grep ELF64 > ' '/tmp/antman_pin_x64')


def sftp_download_file(sshclient=None, filepath='', savepath=''):
    sftp = sshclient.open_sftp()
    sftp.get(filepath, savepath)
    return savepath


def sftp_upload_file(sshclient=None, filepath='', savepath=''):
    sftp = sshclient.open_sftp()
    sftp.put(filepath, savepath)
    return savepath

#def get_file_size(sshclient=None,filepath=''):
#    _, stdout, _ = sshclient.exec_command('sleep 1 && stat --format=%s ' + filepath)
#    if ''.join(stdout.readlines()).startswith('4'):
#        platform = 1
#    else:
#        platform = 0
#    return platform

