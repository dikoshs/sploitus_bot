domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-).(?:[A-Za-z]{2,})$"
ipv4_regex = r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
ipv6_regex = r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9]))$"