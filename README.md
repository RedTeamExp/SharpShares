# Sharp Shares

## Description

```
用于列出当前域中所有计算机的网络共享信息（如果可读）。也可以将所有计算机名称转换为IP地址。
```

## Usage

`SharpShares.exe ips` - 以以下格式输出计算机信息 `$HOSTNAME: $IP`

`SharpShares.exe shares` - 在域中的每台计算机上查询网络共享，以及当前用户是否可以读取它们。

## Example

```
> .\SharpShares.exe shares

Shares for WIN-E9V6E2B5IFM:
        [--- Unreadable Shares ---]
		IPC
	[--- Listable Shares --- ]
		ADMIN$
		C$
		NETLOGON
		SYSVOL
```

```
> .\SharpShares.exe ips
WIN-E9V6E2B5IFM: 192.168.193.208
```



