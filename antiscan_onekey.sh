#!/usr/bin/env bash
# @Author: Seaky
# @Date:   2020/11/27 15:37

##########
# config #
##########

PROJECT_NAME="antiscan"
ROOT_DIR=${HOME:-/tmp}
PROJECT_DIR=${ROOT_DIR}/.${PROJECT_NAME}

[ -d "$PROJECT_DIR" ] || mkdir $PROJECT_DIR

# 敏感网卡
SENSITIVE_NIS="all"
# 敏感外网IP
SENSITIVE_ADDRESS="0.0.0.0/0"
# 敏感端口
SENSITIVE_TCP_PORTS="21:23,69,80,110,123,443,1080,1433,3128,3306,3389,6379,8080"
# ping -s 100 可以将自己加入信任名单
TRUST_ICMP_LENGTH=${TRUST_ICMP_LENGTH:-100}
# 添加信任网络
TRUST_NETWORK="127.0.0.0/8"
THREAT_NETWORK=""

LOG_DIR="/var/log"
LOG_FILE=${LOG_DIR}/${PROJECT_NAME}.log
RSYSLOG_CONFIG_DIR="/etc/rsyslog.d"
LOGROTATE_CONFIG_DIR="/etc/logrotate.d"
INCRON_TABLE="/var/spool/incron/root"

DOG_URL="https://github.com/sseaky/AntiScan/raw/master/antiscan_dog.sh"
DOG_PATH="/usr/bin/${PROJECT_NAME}_dog.sh"
LOCK_PATH=${ROOT_DIR}/.${PROJECT_NAME}.lock

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
    unset alias_name default_value question _value _input value_name
    flag_allow_none=false
    flag_yon=false
    flag_echo=false
    while getopts "a:d:nq:v:l:y" _opt
    do
        case $_opt in
            a) alias_name="$OPTARG" ;;
            d) default_value="$OPTARG" ;;
            l) list="$OPTARG" ;;
            n) flag_allow_none=true ;;
            o) flag_echo=true ;;
            q) question="$OPTARG" ;;
            v) value_name="$OPTARG" ;;
            y) flag_yon=true ;;
        esac
    done

    [ -z "$value_name" ] && show_error "No 'value_name' provide in ${FUNCNAME[0]}" && exit 1
    [ -z "$alias_name" ] && alias_name="${COLOR_GREEN}<${value_name}>${COLOR_END}" || alias_name="${COLOR_GREEN}<${value_name}>${COLOR_END} ($alias_name)"
    if $flag_yon; then
        list="Yes No"
#        [ -z "$question" ] && question="Yes or No?"
    fi
    if [ -n "$list" ]; then
        flag_allow_none=false
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
    func_input_param -v TRUST_ICMP_LENGTH -a "magic length of icmp" -d $TRUST_ICMP_LENGTH
    func_input_param -v TRUST_NETWORK -d $TRUST_NETWORK -a "permanent trust network"

    if [ -n "$SSH_CLIENT" ]; then
        CURRENT_SSH_IP=`echo $SSH_CLIENT | awk '{print $1}'`
        func_input_param -v CURRENT_SSH_IP -a "current login source ip" -n -d $CURRENT_SSH_IP
    else
        func_input_param -v CURRENT_SSH_IP -a "current login source ip" -n
    fi

    [ -s "$IPSET_SAVE_FILE" ] && func_input_param -v flag_ipset_restore -y -a "$TRUST_FILE is exist" -q "Restore it?" || flag_ipset_restore=false

#    [ -s "$TRUST_FILE" ] && func_input_param -v flag_import_trust -y -q "Import items in $TRUST_FILE?"
#    $flag_import_trust && TRUST_NETWORK=$(sort_list $TRUST_NETWORK" "`cat "$TRUST_FILE" | awk -F "," '/^[0-9]+/{print $1}' | xargs`)
#    [ -s "$THREAT_FILE" ] && func_input_param -v flag_import_threat -y -q "Import items in $THREAT_FILE?"
#    $flag_import_trust && THREAT_NETWORK=$(sort_list $THREAT_NETWORK" "`cat "$THREAT_FILE" | awk -F "," '/^[0-9]+/{print $1}' | xargs`)

    show_param SENSITIVE_NIS SENSITIVE_ADDRESS SENSITIVE_TCP_PORTS TRUST_ICMP_LENGTH TRUST_NETWORK THREAT_NETWORK CURRENT_SSH_IP flag_ipset_restore
    [ -n "$CURRENT_SSH_IP" ] && TRUST_NETWORK=`sort_list "$TRUST_NETWORK $CURRENT_SSH_IP"`
}


########
# main #
########

set_iptables(){
    show_process Set iptables rules

    `quite_exec iptables -L ${PROJECT_NAME}` && iptables -F ${PROJECT_NAME} || iptables -N ${PROJECT_NAME}
    iptables -A ${PROJECT_NAME} -m set --match-set ${PROJECT_NAME}_trust src -m comment --comment "accept ${PROJECT_NAME} trust" -j ACCEPT
    iptables -A ${PROJECT_NAME} -p icmp -m length --length $(( $TRUST_ICMP_LENGTH + 28 )) -m comment --comment "mark ${PROJECT_NAME}_trust" -j LOG --log-prefix "${PROJECT_NAME}_trust: "
    iptables -A ${PROJECT_NAME} -p tcp -m multiport --dports `tr_space2comma ${SENSITIVE_TCP_PORTS}` -m comment --comment "mark ${PROJECT_NAME}_threat" -j LOG --log-prefix "${PROJECT_NAME}_threat: "
    iptables -A ${PROJECT_NAME} -m set --match-set ${PROJECT_NAME}_threat src -m comment --comment "drop ${PROJECT_NAME} threat" -j DROP

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
    show_process Set ipset rules
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
\$template ${PROJECT_NAME}_tpl,"%timestamp:::date-unixtimestamp% %timestamp:::date-mysql% %timestamp% %msg:::drop-last-if%\n"

:msg, ereregex, "${PROJECT_NAME}_(trust|threat):" ${LOG_DIR}/${PROJECT_NAME}.log;${PROJECT_NAME}_tpl
& ~

EOF
    /etc/init.d/rsyslog restart
}

set_incron(){
    INCRON_ALLOW="/etc/incron.allow"
    if [ -f "$INCRON_ALLOW" ]; then
        `grep -q "^root" $INCRON_ALLOW` || (echo root >> $INCRON_ALLOW)
    fi

    create_parent ${INCRON_TABLE}
    quite_exec grep "${LOG_FILE}" ${INCRON_TABLE}
    if [ $? -ne 0 ]
    then
        cat > ${INCRON_TABLE} <<-EOF
${LOG_FILE} IN_MODIFY flock -xn $LOCK_PATH $DOG_PATH -r -f \$@
EOF
    fi
    /etc/init.d/incron restart
}

set_logrotate(){
    logrotate_config=${LOGROTATE_CONFIG_DIR}/${PROJECT_NAME}
    cat > ${logrotate_config} <<-EOF
${LOG_DIR}/LOGROTATE_CONFIG_DIR {
    weekly
    rotate 3
    missingok
    notifempty
    compress
    nocreate
}
EOF
}

install_dog(){
    show_process Install `basename $DOG_PATH`
#    cp ${PROJECT_NAME}_dog.sh $DOG_PATH
    wget -qO $DOG_PATH $DOG_URL
    chmod +x $DOG_PATH
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
    check_package rsyslogd rsyslog
    check_package logrotate
    check_package ipset
    check_package incrontab incron
    check_package flock util-linux
    prompt_param
    set_ipset
    set_iptables
    set_rsyslog
    install_dog
    set_incron
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
    echo `basename $0` {install|uninstall|update}
}

check_root

case $1 in
install|uninstall|update)
    $1
    ;;
*)
    show_useage;;
esac

