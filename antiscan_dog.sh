#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2020/11/30 19:43

##########
# config #
##########

VERSION=20201214

DEBUG=false

PROJECT_NAME="antiscan"
ROOT_DIR="/tmp"
PROJECT_DIR=${ROOT_DIR}/.${PROJECT_NAME}

[ -d "$PROJECT_DIR" ] || mkdir $PROJECT_DIR

LOG_DIR="/var/log"
LOG_FILE=${LOG_DIR}/${PROJECT_NAME}.log

LASTSTAMP_FILE=${PROJECT_DIR}/laststamp
THREAT_FILE=${PROJECT_DIR}/threat.csv
THREAT_FILE_NEW=${THREAT_FILE}.new
FLAG_THREAT_FILE=${PROJECT_DIR}/flag_threat
TRUST_FILE=${PROJECT_DIR}/trust.csv
TRUST_FILE_NEW=${TRUST_FILE}.new
FLAG_TRUST_FILE=${PROJECT_DIR}/flag_trust
IPSET_SAVE_FILE=${PROJECT_DIR}/ipset.save

INCRON_TABLE="/var/spool/incron/root"

# 每次读入日志行数，倒数
READ_LINE=20

# 统计列表保存时长
DETAIL_HISTORY=$(( 3600 * 24 * 7))

## ipset超时
TIMEOUT_THREAT=$(( 3600 * 24 * 1 ))
TIMEOUT_TRUST=$(( 3600 * 24 * 14 ))


######
# do #
######

check_root(){
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root!" 1>&2
        exit 1
    fi
}

[ -d "$PROJECT_DIR" ] || mkdir $PROJECT_DIR
[ -f "$LASTSTAMP_FILE" ] || touch $LASTSTAMP_FILE


analyse(){
    $DEBUG && echo --function ${FUNCNAME[0]}--
    if [ ! -s "$LOG_FILE" ]; then exit; fi

    ( $DEBUG || $FLAG_PARSE_WHOLE_LOG ) && laststamp=0 || read laststamp <<< `head -n 1 $LASTSTAMP_FILE`

    [ -f "${TRUST_FILE_NEW}" ] && rm ${TRUST_FILE_NEW}
    [ -f "${THREAT_FILE_NEW}" ] && rm ${THREAT_FILE_NEW}

    $FLAG_PARSE_WHOLE_LOG && GET_CONTENT="cat ${LOG_FILE}*" || GET_CONTENT="tail -n $READ_LINE $LOG_FILE"

    $GET_CONTENT |
        sed -r 's/([0-9]{10,10})\s+(\S+).*antiscan_([^ :]+).*?SRC=(\S+).*?LEN=(\S+).*?PROTO=(\S+)(.*)/\1 \2 \3 \4 \5 \6 \7/g' |
        awk -v lslf=$LASTSTAMP_FILE -v ltst=$laststamp -v pn=$PROJECT_NAME \
            -v thfn=$THREAT_FILE_NEW -v trfn=$TRUST_FILE_NEW \
            -v tmthreat=$TIMEOUT_THREAT -v tmtrust=$TIMEOUT_TRUST \
            -v isf=$IPSET_SAVE_FILE \
            -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN {}
/.+/{
if(debug){print $0};
unixstamp=$1;datetime=$2;catalog=$3;ip=$4;len=$5;proto=$6;misc=$7;
if (unixstamp>ltst)
    {
    if(catalog=="trust")
        {trust_objs[ip",ip"]=ip;trust_objs[ip",count"]+=1; trust_objs[ip",unixstamp"]=unixstamp;trust_objs[ip",datetime"]=datetime;
        trust_ips[ip]=1;
        change["trust"]+=1;
        }
    else if(catalog=="threat")
        {threat_objs[ip",ip"]=ip; threat_objs[ip",count"]+=1; threat_objs[ip",unixstamp"]=unixstamp;
        threat_objs[ip",datetime"]=datetime;
        threat_ips[ip]=1;
        cmd="echo "$8" | sed s/DPT=//gI"; cmd | getline port; close(cmd);
        threat_objs[ip",port"]=threat_objs[ip",port"]" "port;
        change["threat"]+=1;
        }
    }
}
END{
if(debug){print "  --threat--"};
i=1;
for(ip in threat_ips)
    {
    if(i==1){system(": > "thfn)}
    i+=1;
    if(debug){print ip};
    system("ipset add --exist "pn"_threat "ip" timeout "tmthreat);
    cmd="echo "threat_objs[ip",port"]" | tr \" \" \"\\n\" | grep -v ^$ | sort -n | uniq | xargs ;";
    cmd | getline ports;
    close(cmd);
    threat_objs[ip",port"]=ports;
    system("echo "ip","threat_objs[ip",count"]","threat_objs[ip",datetime"]","threat_objs[ip",unixstamp"]","ports" >> "thfn)
    last_ip=ip
    }
if(debug){print "  --trust--"};
i=1;
for(ip in trust_ips)
    {
    if(i==1){system(": > "trfn)}
    i+=1;
    if(debug){print ip};
    system("ipset add --exist "pn"_trust "ip" timeout "tmtrust);
    system("ipset del -q "pn"_threat "ip);
    system("echo "ip","trust_objs[ip",count"]","trust_objs[ip",datetime"]","trust_objs[ip",unixstamp"]",0 >> "trfn)
    }
if(!debug){
    system("echo "unixstamp" > "lslf);
    }
if (change["trust"]+change["threat"] > 0){system("ipset -q save > "isf)}
if(debug){
    print "change_trust:"change["trust"]", change_threat:"change["threat"];
}
}
'
}

merge(){
    $DEBUG && echo --function ${FUNCNAME[0]}--

    now_stamp=`date +%s`

    if [ -f "${TRUST_FILE_NEW}" ]
    then
        [ -f "$TRUST_FILE" ] || touch $TRUST_FILE
        cat "$TRUST_FILE" "$TRUST_FILE_NEW" |
            awk -F "," -v ns=$now_stamp -v dh=$DETAIL_HISTORY \
                -v trf=$TRUST_FILE \
                -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN{
if(debug){print "  --trust file--"};
}
/^[0-9]+/{
if(debug){print $0};
    ip=$1;count=$2;datetime=$3;unixstamp=$4;port=$5;
    trust_ips[ip]=1;
    trust_objs[ip",ip"]=ip; trust_objs[ip",count"]+=count; trust_objs[ip",unixstamp"]=unixstamp;
    trust_objs[ip",datetime"]=datetime; ports=0;
}
END{
system("echo ip,count,datetime,unixstamp,port > "trf)
for (ip in trust_ips)
    {
    if (ns - trust_objs[ip",unixstamp"] < dh)
        system("echo "ip","trust_objs[ip",count"]","trust_objs[ip",datetime"]","trust_objs[ip",unixstamp"]","ports" >> "trf)
    }
}
'
        $DEBUG || rm ${TRUST_FILE_NEW}
    fi

    if [ -f "$THREAT_FILE_NEW" ]
    then
        [ -f "$THREAT_FILE" ] || touch $THREAT_FILE
        cat "$THREAT_FILE" $THREAT_FILE_NEW |
            awk -F "," -v ns=$now_stamp -v dh=$DETAIL_HISTORY \
                -v thf=$THREAT_FILE \
                -v debug=`$DEBUG && echo 1 || echo 0` \
'
BEGIN{
if(debug){print "  --threat file--"};
}
/^[0-9]+/{
if(debug){print $0};
    ip=$1;count=$2;datetime=$3;unixstamp=$4;port=$5;
    threat_ips[ip]=1;
    threat_objs[ip",ip"]=ip; threat_objs[ip",count"]+=count; threat_objs[ip",unixstamp"]=unixstamp;
        threat_objs[ip",datetime"]=datetime;
        threat_objs[ip",port"]=threat_objs[ip",port"]" "port;
}
END{
system("echo ip,count,datetime,unixstamp,port > "thf)
for (ip in threat_ips)
    {
    cmd="echo "threat_objs[ip",port"]" | tr \" \" \"\\n\" | grep -v ^$ | sort -n | uniq | xargs ";
    cmd | getline ports;
    close(cmd)
    threat_objs[ip",port"]=ports;
    if (ns - threat_objs[ip",unixstamp"] < dh)
        system("echo "ip","threat_objs[ip",count"]","threat_objs[ip",datetime"]","threat_objs[ip",unixstamp"]","ports" >> "thf)
    }
}
'
        $DEBUG || rm $THREAT_FILE_NEW
    fi

}

show_usage(){
    echo
    echo "Usage:"
    echo "  -d    Debug mode"
    echo "  -r    Run"
    echo "  -s    Show statistic"
    echo "  -t    Show statistic with location, need python >= 3.5"
    echo "  -f    Log file. default ${LOG_FILE}"
    echo "  -w    Parse whole log file"
    echo "  -x    Remove trust ip"
    echo "  -y    Remove threat ip"
    echo
    echo "Tips:"
    echo "  Show statistic"
    echo "    sudo antiscan_dog.sh -s"
    echo
    echo "  Comment/uncomment the item in root's incrontab to disable/enable the trigger:"
    echo "    sudo incrontab -e"
    echo
    echo "  Alter iptables to customize sensible ports "
    echo "    sudo iptables -nvL --line-number "
    echo
    echo "  Alter ipset to customize trust/threat list "
    echo "    sudo ipset list "
    echo
}

remove_ip(){
    [ "$1" = "trust" ] && fn=$TRUST_FILE || fn=$THREAT_FILE
    ipset -q del ${PROJECT_NAME}_$1 $2
    [ -s "$fn" ] && sed -i "/^$2.*$/d" $fn
    ipset -q save > $IPSET_SAVE_FILE
}

show_stat(){
    show_file(){
    if [ -f "$1" ]
    then
        echo -- $1 --
        cat $1 | sort -n -t "," -k4,4n | awk -F "," '{
        if (NR==1){datatime=$3}else{datatime=substr($3,3,2)"."substr($3,5,2)"."substr($3,7,2)" "substr($3,9,2)":"substr($3,11,2)":"substr($3,13,2)}
        printf "%-15s  %-5s  %-17s  %-10s  %s\n",$1,$2,datatime,$4,$5}'
    fi
    }
    show_file $THREAT_FILE
    show_file $TRUST_FILE
}

show_stat_py(){
    py_script=${PROJECT_DIR}/antiscan_ip.py
    py_url="https://github.com/sseaky/AntiScan/raw/master/antiscan_ip.py"
    ipdb_file=${PROJECT_DIR}/ipipfree.ipdb
    ipdb_md5="aab5c5e2f5a8647694fcc0fdd7e9fb39"
    ipdb_url="https://github.com/sseaky/AntiScan/releases/download/0.1/ipipfree.tar.gz"

    flag_down=true
    which python3 > /dev/null 2>&1 || ( echo "Need python >= 3.5" && exit )
    python3 -c "import ipdb" > /dev/null 2>&1 || ( echo "Need python module ipdb. sudo pip3 install ipip-ipdb" && exit )
    [ -f "${ipdb_file}" ] && [ "`md5sum ${ipdb_file} | awk '{print $1}'`" = $ipdb_md5 ] && flag_down=false
    if $flag_down; then
        rm $ipdb_md5 > /dev/null 2>&1
        wget $ipdb_url
        tar zxf ipipfree.tar.gz
        mv ipipfree.ipdb ${PROJECT_DIR}/
        rm ipipfree.tar.gz
    fi

    [ -f "${py_script}" ] || wget $py_url
    
    python3 ${py_script}
}

main(){
    check_root
    analyse
    merge
}

FLAG_RUN=false
FLAG_PARSE_WHOLE_LOG=false
while getopts 'df:hrstwx:y:' opt
do
    case $opt in
        d) DEBUG=true ;;
        f) logfile=$OPTARG ;;
        r) FLAG_RUN=true ;;
        s) show_stat; exit ;;
        t) show_stat_py; exit ;;
        w) FLAG_PARSE_WHOLE_LOG=true ;;
        x) remove_ip trust $OPTARG; exit ;;
        y) remove_ip threat $OPTARG; exit ;;
        *) show_usage; exit ;;
    esac
done

[ -n "$logfile" ] && LOG_FILE=$logfile

$FLAG_RUN && main || show_usage


