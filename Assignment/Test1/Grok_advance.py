a = """<b>SQL Monitoring Alert:</b>
Time : 2/12/2024 4:15:53 PM
Alert ID : 202421216155315
TGR-PRD-BWRECDB(101.200.15.123,1444) : [High]Blocked process expectancy is under 1secs ( Current: 0.00 )
Please follow up immediately !!!
"""
b = """<b>SQL Monitoring Alert:</b>
Time : 2/11/2024 9:45:38 PM 
Alert ID : 20242112145385
TGR-PRD-CRMDB(103.143.15.205) : [High]Blocking Session(s) are running over 300 seconds. ( Current Max(sec): 1,227.00 )
Please follow up immediately !!
"""
def read_log(log_message):
    line_number = 0
    Grok_table = {} 
    log_message = log_message.lower()
    
    if "blocked process" in log_message or "blocking session(s)" in log_message:
            lines = log_message.split('\n')
            # print(lines)

            for line in lines:
                line_number += 1

                if line_number == 1:
                    start_tag_index = line.find('<b>') + len('<b>')
                    end_tag_index = line.find(':')
                    header = line[start_tag_index:end_tag_index].strip()
                    Grok_table["Header"] = header
                if line_number ==2:
                    start_tag_index = line.find("time : ")
                    time = line[start_tag_index + len("time : "):].strip()
                    Grok_table["Time"] = time
                if line_number == 4:
                    port_tag = line.find("(")
                    end_port_tag = line.find(")")
                    if "," not in line[port_tag:end_port_tag]:
                        print("Port does not Exist")
                        end_tag_index = line.find("(")
                        host_name = line[0:end_tag_index]
                        Grok_table["Host_name"] = host_name
                        end_tag_index2 = line.find("[")
                        ip = line[end_tag_index+1:end_tag_index2-4]
                        Grok_table["IP Address"] = ip
                        Grok_table["Port"] = "-"
                    else:
                        print("Port Exist")
                        end_tag_index = line.find("(")
                        host_name = line[0:end_tag_index]
                        Grok_table["Host_name"] = host_name
                        end_tag_index2 = line.find(",")
                        ip = line[end_tag_index+1:end_tag_index2]
                        Grok_table["IP Address"] = ip
                        end_tag_index3 = line.find(")")
                        port = line[end_tag_index2+1:end_tag_index3]
                        Grok_table["Port"] = port
                    # print(port_tag)
                    # print(end_port_tag)
            for key, value in Grok_table.items():  
                print(f"{key}: {value}")
            print("\n")

    else:
        print("No blocked or blocking")

read_log(a)
read_log(b)
