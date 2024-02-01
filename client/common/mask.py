# -* - coding: UTF-8 -* -
# ! /usr/bin/python
def mask_ip(ip, n):
    # n=1, mask port, 127.0.0.1:3131->127.0.0.1:1131 = 127.0.0.1:*->127.0.0.1:*
    # n=2, mask 8 + port, 127.0.0.1:3131->127.0.0.1:1131 = 127.0.0.*:*->127.0.0.*:*
    if not ip:
        return ip
    if len(ip.split('->')) >= 2:
        ip_1 = ip.split('->')[0]
        ip_2 = ip.split('->')[1]
        if n == 1:
            # 1, 有port
            if ':' in ip_1:
                ip_1 = ip_1.split(':')[0] + ':*'
            if ':' in ip_2:
                ip_2 = ip_2.split(':')[0] + ':*'
            return ip_1 + '->' + ip_2
        if n == 2:
            # 1, 有port
            if ':' in ip_1:
                ip_1 = ip_1[:ip_1.rfind('.')] + '.*:*'
            else:
                # 2, 无port
                ip_1 = ip_1[:ip_1.rfind('.')] + '.*'
            if ':' in ip_2:
                ip_2 = ip_2[:ip_2.rfind('.')] + '.*:*'
            else:
                ip_2 = ip_2[:ip_2.rfind('.')] + '.*'
            return ip_1 + '->' + ip_2
    else:
        # 有冒号无冒号
        if ':' in ip:
            if n == 1:
                ip = ip.split(':')[0] + ':*'
            if n == 2:
                ip = ip[:ip.rfind('.')] + '.*:*'
        return ip


def mask_path(p, n):
    n = 1
    # n=0, mask . , /proc/irq/188/smp_affinity.log = /proc/irq/188/*.log
    # n=1, mask 1 /, /proc/irq/188/smp_affinity = /proc/irq/188/*
    # n=2, mask 2 //, /proc/irq/188/smp_affinity = /proc/irq/*/*
    if n == 0:
        if '/' in p:
            f_index = p.rfind('/')
            first = p[:f_index] + '/'
            last = p[f_index:]
            suffix = last.rfind('.')
            if suffix != -1:
                last = '*' + last[suffix:]
            return first + last
        else:
            suffix = p.rfind('.')
            if suffix != -1:
                p = '*' + p[suffix:]
            return p

    if n == 1:
        # 1, 有/
        if '/' in p:
            return p[:p.rfind('/')] + '/*'
        else:
            return '*'
    if n == 2:
        c = p.count('/')
        if c >= 2:
            rfind_1_index = p.rfind('/')
            return p[:p.rfind('/', 0, rfind_1_index)] + '/*'
        elif c == 1:
            return '/*'
        else:
            return '*'
    return p