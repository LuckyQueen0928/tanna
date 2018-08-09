# shutdown.sh
sudo kill -9 `ps -aux | grep 8080 |grep 'root' |awk '{print $2}'`