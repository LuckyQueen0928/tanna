import zipfile
import os
import shutil

def unzip(zipfilepath='', unzippath=''):
    with zipfile.ZipFile(zipfilepath, 'r') as z:
        z.extractall(unzippath)
    print unzippath

def repitname(unzippath='', hashname=''):
    for filename in os.listdir(unzippath):
        path = unzippath + '/' + filename
        newname = unzippath + '/' + hashname
        if os.path.isdir(path):
            try:
                os.rename(path, newname)
            except OSError, e:
                shutil.rmtree(newname)
                os.rename(path, newname)

def get_filename_from_path(path=''):
    return os.path.basename(path)
