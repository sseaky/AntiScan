#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2020/11/27 15:37

##########
# config #
##########

PROJECT_NAME="antiscan"
ROOT_DIR='/root'
PROJECT_DIR=${ROOT_DIR}/.${PROJECT_NAME}

GITHUB_MIRROR=${GITHUB_MIRROR:-https://github.com}

[ -d "$PROJECT_DIR" ] || mkdir $PROJECT_DIR

# 敏感网卡
SENSITIVE_NIS="eth0"
# 敏感外网IP
SENSITIVE_ADDRESS="0.0.0.0/0"
# 敏感端口
SENSITIVE_TCP_PORTS="21:23,69,80,110,443,1080,1433,3128,3306,3389,6379,8080,9999,59999"
# ping -s 100 可以将自己加入信任名单
MAGIC_PING_LENGTH=${MAGIC_PING_LENGTH:-100}
# 添加信任网络
TRUST_NETWORK="127.0.0.0/8"
THREAT_NETWORK=""

# 详细日志保存天数，日志太多会消耗性能
DETAIL_HISTORY_DAY=7

grep -i 'centos' /etc/os-release >> /dev/null && OS='centos' || OS='ubuntu'

LOG_DIR="/var/log"
LOG_FILE_TRUST=${LOG_DIR}/${PROJECT_NAME}_trust.log
LOG_FILE_THREAT=${LOG_DIR}/${PROJECT_NAME}_threat.log
RSYSLOG_CONFIG_DIR="/etc/rsyslog.d"
LOGROTATE_CONFIG_DIR="/etc/logrotate.d"
INCRON_TABLE="/var/spool/incron/root"
[ "$OS" = "centos" ] && CRON_TABLE="/var/spool/cron/root" || CRON_TABLE="/var/spool/cron/crontabs/root"

DOG_URL="${GITHUB_MIRROR}/sseaky/AntiScan/raw/master/antiscan_dog.sh"
DOG_PATH="/usr/bin/${PROJECT_NAME}_dog.sh"
LOCK_PATH_TRUST=${PROJECT_DIR}/.lock_trust
LOCK_PATH_THREAT=${PROJECT_DIR}/.lock_threat

ANTISSH_URL="${GITHUB_MIRROR}/sseaky/AntiScan/raw/master/antissh.sh"
ANTISSH_PATH="/usr/bin/antissh.sh"

PY_URL="${GITHUB_MIRROR}/sseaky/AntiScan/raw/master/antiscan_ip.py"
PY_PATH=${PROJECT_DIR}/antiscan_ip.py

THREAT_FILE=${PROJECT_DIR}/threat.csv
TRUST_FILE=${PROJECT_DIR}/trust.csv
IPSET_SAVE_FILE=${PROJECT_DIR}/ipset.save

#########
# tools #
#########

set_text_color(){
    COLOR_RED='\E[31m'
    COLOR_GREEN='\E[32m'
    COLOR_YELLOW='\E[33m'
    COLOR_BLUE='\E[34m'
    COLOR_PINK='\E[35m'
    COLOR_CYAN='\E[36m'
    COLOR_GREEN_LIGHTNING='\033[32m \033[05m'
    COLOR_END='\E[0m'
}
set_text_color

show_process(){
    echo -e "${COLOR_GREEN}- INFO: $*${COLOR_END}"
}

show_error(){
    echo
    echo -e "${COLOR_RED}! ERROR: $*${COLOR_END}"
}

show_warn(){
    echo
    echo -e "${COLOR_YELLOW}* WARN: $*${COLOR_END}"
}

create_parent(){
    mkdir -p "${1%/*}"
}

is_number(){
    [ -n "`echo $1 | grep -E "^[0-9]+$"`" ] && return 0 || return 1
}

check_root(){
    if [ "$EUID" -ne 0 ]; then
        show_error "This script must be run as root!" 1>&2
        exit 1
    fi
}

check_package(){
    read cmd package action<<< $*
    [ -z "$cmd" ] && exit 1
    [ -z "$package" ] && package=$cmd
    [ "$action" = "quit" ] && show_error "$package is not exist" && exit 1
    if ! `quite_exec which $cmd`
    then
        show_process Install $package
        apt install -y $package
        [ $? -ne 0 ] && show_error "Install $package fail" && exit 1
    fi
}

quite_exec(){
    eval $@ >> /dev/null 2>&1
}

quite_rm(){
    quite_exec rm -rf $*
}

sort_list(){
    echo $@ | tr " " "\n" | grep -v "^$" | sort | uniq | xargs
}

tr_comma2space(){
    echo "$*" | tr "," " "
}

tr_space2comma(){
    echo "$*" | tr " " ","
}

get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

func_input_param(){
    local OPTIND
    unset alias_name default_value question _value _input value_name list
    flag_allow_none=false
    flag_yon=false
    flag_echo=false
    while getopts "a:d:nq:v:l:yo" _opt
    do
        case $_opt in
            a) alias_name="$OPTARG" ;;      # 变量提示信息
            d) default_value="$OPTARG" ;;   # 默认值
            l) list="$OPTARG" ;;            # 答案列表
            n) flag_allow_none=true ;;      # 允许无输入
            o) flag_echo=true ;;            # 回显结果
            q) question="$OPTARG" ;;        # 自定义问题
            v) value_name="$OPTARG" ;;      # 返回变量名
            y) flag_yon=true ;;             # 是否问题
        esac
    done

    [ -z "$value_name" ] && show_error "No 'value_name' provide in ${FUNCNAME[0]}" && exit 1
    [ -z "$alias_name" ] && alias_name="${COLOR_GREEN}<${value_name}>${COLOR_END}" || alias_name="${COLOR_GREEN}<${value_name}>${COLOR_END} ($alias_name)"
    if $flag_yon; then
        list="Yes No"
#        [ -z "$question" ] && question="Yes or No?"
    fi
    if [ -n "$list" ]; then
        # flag_allow_none=false
        [ -z "$question" ] && question="Please choice ${COLOR_PINK}ID${COLOR_END} of ${alias_name}"
        [ -z "$default_value" ] && default_value=1
    fi

    [ -z "$question" ] && question="Please input ${alias_name}"
    [ -n "$default_value" ] && info="(Default : ${default_value})" || info=""

    while true
    do
        if [ -n "$list" ]
        then
            echo -e "Choice of ${COLOR_GREEN}${alias_name}${COLOR_END}"
            i=0
            for item in `tr_comma2space $list`
            do
                i=$(($i+1))
                items[$i]=$item
                echo "  $i) $item"
            done
        fi

        echo -n -e "${question} ${info}    "
        read _input

        [ -n "$_input" ] && _value=${_input} || _value=${default_value}

        [ -z "${_value}" ] && ! $flag_allow_none && show_warn "Argument ${alias_name} can not be empty." && continue

        [ -n "$list" ] && ! `is_number $_value` && show_warn "$_value is not a number id." && continue
        [ -n "$list" ] && [ $_value -gt $i -o $_value -le 0 ] && show_warn "$_value is out of choice." && continue
        break
    done

    if [ -n "$list" ]; then
        if $flag_yon; then
            [ "$_value" -eq 1 ] && _value=true || _value=false
        else
            _value=${items[$_value]}
        fi
    fi

    $flag_echo && echo -e "${COLOR_GREEN}${value_name}${COLOR_END}: ${COLOR_YELLOW}${_value}${COLOR_END}"
    echo
    eval ${value_name}=\"${_value}\"
}


str_repeat(){
    eval printf -- "$1%0.s" {1..$2}
}

show_banner(){
    local OPTIND
    unset show_author text
    show_author=false
    while getopts "t:a" _opt
    do
        case $_opt in
            a) show_author=true ;;
            t) title="$OPTARG" ;;
        esac
    done

    indent=2
    len=$((${#title} + $indent + $indent))
    author="Seaky"
    title2="Author: $author"
    indent2b=$((($len - ${#title2}) / 2))
    indent2a=$(($len - ${#title2} - $indent2b))
    len2=$((${#title2} + $indent + $indent))
    echo
    echo "+"$(str_repeat "-" $len)"+"
    printf "|%$((${len}+1))s\n" "|"
    printf "|%$((${#title} + $indent))s%$((${indent}+1))s\n" "$title" "|"
    $show_author && printf "|%$((${#title2} + $indent2a))s%$((${indent2b}+1))s\n" "$title2" "|"
    printf "|%$((${len}+1))s\n" "|"
    echo "+"$(str_repeat "-" $len)"+"
    echo
}

show_param(){
    maxlen=0
    for x in $*; do [ ${#x} -gt $maxlen ] && maxlen=${#x}; done
    title="Check your input"
    echo "$(str_repeat "=" 10) ${title} $(str_repeat "=" 10)"
    echo
    for x in $*; do
        echo -e "${COLOR_GREEN}$x${COLOR_END}$(str_repeat "\ " $(($maxlen+1-${#x}))): ${!x}"
    done
    echo
    echo $(str_repeat "=" $((20 + 2 + ${#title})))
    echo
    echo "Press any key to Continue...or Press Ctrl+c to Cancel"
    char=`get_char`
}


##########
# prompt #
##########


prompt_param(){
    clear
    show_banner -a -t "AntiScan Install"
    show_process "Start config"
    echo

    func_input_param -v SENSITIVE_NIS -a "sensitive interface: $(ls /sys/class/net | xargs)" -d $SENSITIVE_NIS
    [ "$SENSITIVE_NIS" = "all" ] && iptables_option_nis="" || iptables_option_nis="-i $SENSITIVE_NIS"

    func_input_param -v SENSITIVE_ADDRESS -a "sensitive ip" -d $SENSITIVE_ADDRESS
    func_input_param -v SENSITIVE_TCP_PORTS -a "sensitive ports" -d $SENSITIVE_TCP_PORTS
    func_input_param -v MAGIC_PING_LENGTH -a "magic length of icmp" -d $MAGIC_PING_LENGTH
    func_input_param -v TRUST_NETWORK -d $TRUST_NETWORK -a "permanent trust network"

    if [ -n "$SSH_CLIENT" ]; then
        CURRENT_SSH_IP=`echo $SSH_CLIENT | awk '{print $1}'`
        func_input_param -v CURRENT_SSH_IP -a "current login source ip" -n -d $CURRENT_SSH_IP
    else
        func_input_param -v CURRENT_SSH_IP -a "current login source ip" -n
    fi

    [ -s "$IPSET_SAVE_FILE" ] && func_input_param -v flag_ipset_restore -y -a "$TRUST_FILE is exist" -q "Restore it?" || flag_ipset_restore=false

    # 日志保存天数太多，会增加解析时长
    func_input_param -v DETAIL_HISTORY_DAY -a "threat log days" -d $DETAIL_HISTORY_DAY
    # 公网扫描太多，使用incron解析threat会消耗资源，改用cron每1分钟解析一次。trust还是使用incron
    func_input_param -v THREAT_COPE_METHOD -l "incron cron" -a "threat method" -n
    [ "$THREAT_COPE_METHOD" = "cron" ] && func_input_param -v THREAT_CRON_INTERVAL -a "threat cron interval" -d 1 -n

    func_input_param -v INSTALL_ANTISSH -y -a "install anti ssh module" -n -o
#    [ -s "$TRUST_FILE" ] && func_input_param -v flag_import_trust -y -q "Import items in $TRUST_FILE?"
#    $flag_import_trust && TRUST_NETWORK=$(sort_list $TRUST_NETWORK" "`cat "$TRUST_FILE" | awk -F "," '/^[0-9]+/{print $1}' | xargs`)
#    [ -s "$THREAT_FILE" ] && func_input_param -v flag_import_threat -y -q "Import items in $THREAT_FILE?"
#    $flag_import_trust && THREAT_NETWORK=$(sort_list $THREAT_NETWORK" "`cat "$THREAT_FILE" | awk -F "," '/^[0-9]+/{print $1}' | xargs`)

    show_param SENSITIVE_NIS SENSITIVE_ADDRESS SENSITIVE_TCP_PORTS MAGIC_PING_LENGTH TRUST_NETWORK THREAT_NETWORK CURRENT_SSH_IP \
        DETAIL_HISTORY_DAY THREAT_COPE_METHOD THREAT_CRON_INTERVAL INSTALL_ANTISSH flag_ipset_restore 
    [ -n "$CURRENT_SSH_IP" ] && TRUST_NETWORK=`sort_list "$TRUST_NETWORK $CURRENT_SSH_IP"`
}


########
# main #
########


install_basic_backage(){
    [ "$OS" = "centos" ] && yum install -y epel-release
    [ "$OS" = "centos" ] && yum install -y ipset incrontab mailx jq dos2unix rsyslog logrotate util-linux
    [ "$OS" = "centos" ] || apt install -y ipset incron mailutils jq dos2unix rsyslog logrotate util-linux
    # check_package rsyslogd rsyslog
    # check_package logrotate
    # check_package ipset
    # check_package incrontab incron incrontab
    # check_package flock util-linux
}


set_iptables(){
    show_process Set iptables rules

    `quite_exec iptables -L ${PROJECT_NAME}` && iptables -F ${PROJECT_NAME} || iptables -N ${PROJECT_NAME}
    iptables -A ${PROJECT_NAME} -m set --match-set ${PROJECT_NAME}_trust src -m comment --comment "accept ${PROJECT_NAME} trust" -j ACCEPT
    iptables -A ${PROJECT_NAME} -p icmp -m length --length $(( $MAGIC_PING_LENGTH + 28 )) -m comment --comment "mark ${PROJECT_NAME}_trust" -j LOG --log-prefix "${PROJECT_NAME}_trust: "
    iptables -A ${PROJECT_NAME} -p tcp -m multiport --dports `tr_space2comma ${SENSITIVE_TCP_PORTS}` -m comment --comment "mark ${PROJECT_NAME}_threat" -j LOG --log-prefix "${PROJECT_NAME}_threat: "
    iptables -A ${PROJECT_NAME} -m set --match-set ${PROJECT_NAME}_threat src -m comment --comment "drop ${PROJECT_NAME} threat" -j DROP
    iptables -I FORWARD 1 -m set --match-set ${PROJECT_NAME}_threat src -m comment --comment "drop ${PROJECT_NAME} threat" -j DROP

    cmd="iptables -A INPUT"
    [ -n "$iptables_option_nis" ] && cmd="$cmd $iptables_option_nis"
    [ -n "$SENSITIVE_ADDRESS" ] && cmd="$cmd -d $SENSITIVE_ADDRESS"
    cmd=$cmd" -m comment --comment go_to_${PROJECT_NAME} -j ${PROJECT_NAME} "
    `quite_exec "iptables -nvL INPUT | grep -i ${PROJECT_NAME} | grep -v grep"` ||  $cmd
    
}

ipset_add(){
    read list target timeout <<< $*
    timeout=${timeout:-0}
    `quite_exec ipset -q test $list $target` || ipset -q add $list $target timeout $timeout
}

set_ipset(){
    show_process "Set ipset rules"
    $flag_ipset_restore && (ipset -q restore < $IPSET_SAVE_FILE)
    `quite_exec ipset list -n ${PROJECT_NAME}_trust` || ipset create ${PROJECT_NAME}_trust hash:net hashsize 4096 maxelem 1000000 timeout 0
    `quite_exec ipset list -n ${PROJECT_NAME}_threat` || ipset create ${PROJECT_NAME}_threat hash:net hashsize 4096 maxelem 1000000 timeout 0

    # add trust network
    for trnw in `tr_comma2space $TRUST_NETWORK`; do ipset_add ${PROJECT_NAME}_trust $trnw; done
    for thnw in `tr_comma2space $THREAT_NETWORK`; do ipset_add ${PROJECT_NAME}_threat $thnw; done

    # add ssh client
    [ -n "$SSH_CLIENT" ] && read ip port1 port2 <<< $SSH_CLIENT && [ -n "$ip" ] && ipset_add ${PROJECT_NAME}_trust $ip
}

set_rsyslog(){
    show_process "Set rsyslog"
    rsyslog_config=${RSYSLOG_CONFIG_DIR}/01-${PROJECT_NAME}.conf
    if [ ! -d "$RSYSLOG_CONFIG_DIR" ]; then
        show_error $RSYSLOG_CONFIG_DIR is not exist!
        exit 1
    fi

    cat > ${rsyslog_config} <<-EOF
\$template ${PROJECT_NAME}_tpl,"%timestamp:::date-unixtimestamp% %timestamp:::date-mysql% %timestamp% %msg%\n"

:msg, ereregex, "${PROJECT_NAME}_trust:" ${LOG_FILE_TRUST};${PROJECT_NAME}_tpl
:msg, ereregex, "${PROJECT_NAME}_threat:" ${LOG_FILE_THREAT};${PROJECT_NAME}_tpl
& stop

EOF
    touch ${LOG_FILE_TRUST} && chmod 666 ${LOG_FILE_TRUST}
    touch ${LOG_FILE_THREAT} && chmod 666 ${LOG_FILE_THREAT}
    [ "$OS" = "centos" ] && systemctl restart rsyslog || /etc/init.d/rsyslog restart
}

set_incron_trust(){
    show_process "Set incrontab for trust"
    INCRON_ALLOW="/etc/incron.allow"
    if [ -f "$INCRON_ALLOW" ]; then
        `grep -q "^root" $INCRON_ALLOW` || (echo root >> $INCRON_ALLOW)
    fi
    create_parent ${INCRON_TABLE}

    quite_exec grep "${LOG_FILE_TRUST}" ${INCRON_TABLE}
    if [ $? -ne 0 ]
    then
        cat > ${INCRON_TABLE} <<-EOF
${LOG_FILE_TRUST} IN_MODIFY flock -xn $LOCK_PATH_TRUST $DOG_PATH -r -f \$@
EOF
    fi
    [ "$OS" = "centos" ] && systemctl restart incrond.service || /etc/init.d/incron restart
}

set_incron_threat(){
    show_process "Set incrontab for threat"
    INCRON_ALLOW="/etc/incron.allow"
    if [ -f "$INCRON_ALLOW" ]; then
        `grep -q "^root" $INCRON_ALLOW` || (echo root >> $INCRON_ALLOW)
    fi
    create_parent ${INCRON_TABLE}

    quite_exec grep "${LOG_FILE_THREAT}" ${INCRON_TABLE}
    if [ $? -ne 0 ]
    then
        cat > ${INCRON_TABLE} <<-EOF
${LOG_FILE_THREAT} IN_MODIFY flock -xn $LOCK_PATH_THREAT $DOG_PATH -r -f \$@
EOF
    fi
    /etc/init.d/incron restart
}


# 互联网上扫描很多，对于低配机器，使用incron处理threat会加重负担，可以使用cron代替
# 对于trust仍然保留incron
set_cron_threat(){
    show_process "Set crontab for threat"
    quite_exec grep "${LOG_FILE_THREAT}" ${CRON_TABLE}
    if [ $? -ne 0 ]
    then
        cat >> ${CRON_TABLE} <<-EOF
*/${THREAT_CRON_INTERVAL} * * * * $DOG_PATH -r -f ${LOG_FILE_THREAT}
EOF
    fi
}


set_logrotate(){
    show_process "Set logrotate"
    logrotate_config=${LOGROTATE_CONFIG_DIR}/${PROJECT_NAME}
    cat > ${logrotate_config} <<-EOF
${LOG_FILE_THREAT} {
    weekly
    rotate 3
    missingok
    notifempty
    compress
	copytruncate
    create 666 root root
}
${LOG_FILE_TRUST} {
    weekly
    rotate 3
    missingok
    notifempty
    compress
    copytruncate
    create 666 root root
}
EOF
}

install_dog(){
    show_process Install `basename $DOG_PATH`
#    cp ${PROJECT_NAME}_dog.sh $DOG_PATH
    wget -qO $DOG_PATH $DOG_URL
    wget -qO $PY_PATH $PY_URL
    chmod +x $DOG_PATH
    [ -n "$DETAIL_HISTORY_DAY" ] && sed -i "s/^DETAIL_HISTORY_DAY=.*$/DETAIL_HISTORY_DAY=${DETAIL_HISTORY_DAY}/" $DOG_PATH
}

install_antissh(){
    show_process Install `basename $DOG_PATH`
    wget -qO $ANTISSH_PATH $ANTISSH_URL
    chmod +x $ANTISSH_PATH
    quite_exec grep "${ANTISSH_PATH}" ${CRON_TABLE}
    if [ $? -ne 0 ]
    then
        cat >> ${CRON_TABLE} <<-EOF
*/1 * * * * $ANTISSH_PATH
EOF
    fi
}

show_result(){
    echo
    ipset list -n | xargs echo ipset rules
    echo
    iptables -nvL
}

show_tip(){
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

install(){
    install_basic_backage
    prompt_param
    set_ipset
    set_iptables
    set_rsyslog
    set_logrotate
    install_dog
    set_incron_trust
    if [ "$THREAT_COPE_METHOD" = "incron" ]; then
        set_incron_threat
    else
        set_cron_threat
    fi
    $INSTALL_ANTISSH && install_antissh
    show_process "Install $PROJECT_NAME done."
    show_tip
}

uninstall(){
    quite_exec "iptables --line-numbers -nL INPUT | grep -i go_to_${PROJECT_NAME} | awk '{print \$1}' | xargs iptables -D INPUT "
    quite_exec iptables -F ${PROJECT_NAME}
    quite_exec iptables -X ${PROJECT_NAME}
    quite_exec ipset destroy ${PROJECT_NAME}_trust
    quite_exec ipset destroy ${PROJECT_NAME}_threat
    quite_rm ${LOGROTATE_CONFIG_DIR}/${PROJECT_NAME}
    quite_rm ${RSYSLOG_CONFIG_DIR}/01-${PROJECT_NAME}.conf
    /etc/init.d/rsyslog restart
#    quite_rm ${PROJECT_DIR}
    quite_exec echo : > ${INCRON_TABLE}
    /etc/init.d/incron restart
    show_process "Uninstall $PROJECT_NAME done."
}

update(){
    flag_update=true
    $flag_update && install_dog
    show_process "Update $DOG_PATH done"
}

show_usage(){
    echo "`basename $0` {install|uninstall|update}"
}

check_root


case $1 in
install|uninstall|update)
    $1
    ;;
*)
    show_usage;;
esac

