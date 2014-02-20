#!/bin/bash

export USER_MODULE=myrouter1
export TEST_MODULE=routertests1.srpy

args=`getopt c $*`

if [ $? != 0 ]; then
    echo "Usage: $0 [-c]"
    exit
fi

if [[ $args == " -c --" ]]; then
    echo "Doing cleanup."
    rm -rf pox
    rm -rf srpy
    rm -f *.pyc
    rm -f runreal.sh runtests.sh
    exit
fi
echo "Doing setup."

if [[ ! -d pox ]]; then
    git clone git://github.com/noxrepo/pox pox
else
    cd pox
    git pull
    cd ..
fi

if [[ ! -d srpy ]]; then
    git clone git://github.com/jsommers/srpy srpy
else
    cd srpy
    git pull
    cd ..
fi

(
cat <<EOF
#!/bin/bash
python ./srpy/srpy.py \$@ $USER_MODULE
EOF
) > runreal.sh
chmod +x ./runreal.sh

(
cat <<EOF
#!/bin/bash
python ./srpy/srpy.py \$@ -t -s $TEST_MODULE $USER_MODULE
EOF
) > runtests.sh
chmod +x ./runtests.sh

