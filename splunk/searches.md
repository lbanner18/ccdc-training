# Starter Splunk searches

Replace `index=main` and the host names with the values from the team packet.
These are intentionally small searches you can paste during a timed inject.

## Linux

```spl
index=main sourcetype=linux_secure ("Failed password" OR "authentication failure")
| stats count min(_time) as first max(_time) as last values(src) as sources by user
```

```spl
index=main sourcetype=linux_secure ("Accepted password" OR "Accepted publickey")
| table _time host user src method
| sort - _time
```

```spl
index=main sourcetype=linux_secure ("new user" OR "useradd" OR "adduser")
| table _time host _raw
```

```spl
index=main sourcetype=linux_secure ("sudo:" OR "COMMAND=")
| table _time host user command _raw
| sort - _time
```

```spl
index=main ("Stopped" OR "Failed" OR "Started") (sshd OR nginx OR apache OR named OR mysql)
| table _time host _raw
```

## Windows Security log

```spl
index=main sourcetype=WinEventLog:Security EventCode IN (4624,4625)
| stats count values(src_ip) as source_ips by EventCode Account_Name Logon_Type
```

```spl
index=main sourcetype=WinEventLog:Security EventCode=4720
| table _time Computer Account_Name SubjectUserName
```

```spl
index=main sourcetype=WinEventLog:Security EventCode=4732
| table _time Computer MemberName TargetUserName SubjectUserName
```

```spl
index=main sourcetype=WinEventLog:System EventCode=7045
| table _time Computer Service_Name ImagePath Service_File_Name Account_Name
```

```spl
index=main sourcetype=WinEventLog:Security EventCode IN (4698,1102)
| table _time Computer EventCode SubjectUserName Task_Name _raw
```

