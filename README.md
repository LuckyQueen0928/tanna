
### 在虚拟机内的配置和运行方法

1. 修改源码根目录下`conf.ini`配置文件，修改`NFS_FOLDER`为共享目录地址，修改`DATABASE_URL`为数据库uri，uri里面包含着数据库的类型，用户名，密码，数据库服务器地址及数据库名。
2. 修改`run.sh`shell脚本，修改第一条共享目录挂载指令，更改为当前的共享目录挂载地址及目录，如果已经挂载可去除该指令。修改第二条共享目录权限修改指令，在`sudo chmod 777 `后添加当前的共享目录路径。最后，`sudo python manage.py runserver --host 0.0.0.0 --thread --port 8080`可修改port选项更改web服务运行端口，并访问：http://127.0.0.1:8080访问web服务。


### 数据库迁移命令

如果你更改了数据库管理应用（如从Mysql转为Sqlite）或者需要更新数据库表结构的情况下，
请更改manage.py的数据库url配置，并运行`python manage.py db upgrade`。

### 运行方法

运行`sudo pip install -r requestment`安装pip第三方依赖库
运行`bash run.sh`，输入密码之后，访问http://127.0.0.1:8080

### 配置文件

`config.py` or `conf.ini`

    FLASK_CONFIG=testing
    NFS_FOLDER=/usr/local/nfs/
    #DATABASE_URL=mysql+pymysql://root:LYS1105Tz@localhost:3306/antweb2
    DATABASE_URL=mysql+pymysql://root:123456@192.168.1.129/test2.0

- FLASK_CONFIG ： 要运行config.py的哪一个配置类
- NFS_FOLDER ： 共享目录地址，记得修改`run.sh`的共享目录地址
- DATABASE_URL ： 用于连接数据库的URI
