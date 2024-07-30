#from re import S
import socket
import pickle
import os
#import time
#import struct
import json
import traceback
import hashlib
import maskpass
import copy
#import rsa
import ssl
import Base_Library as Lib
import Base_Library_outside as Libo
import INFO
from loguru import logger
socket.setdefaulttimeout(1800)

def _make_sock(AF,saddr):
	CA_FILE="ca-cert.pem"
	SERVER_CERT_FILE="server-cert.pem"
	CLIENT_KEY_FILE="client-key.pem"
	CLIENT_CERT_FILE = "client-cert.pem"
	context=ssl.SSLContext(ssl.PROTOCOL_TLS)
	context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
	#context.load_verify_locations(CA_FILE)
	context.verify_mode = ssl.CERT_REQUIRED
	context.load_verify_locations(cafile=CA_FILE)
	context.check_hostname = False
	sock=socket.socket(AF,socket.SOCK_STREAM)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	ssock=context.wrap_socket(sock,server_hostname=saddr, server_side=False)
	return ssock

def _token_exchange(sock,self_pub):
	return (None,None)
	#"""
	#encd_self_pub=pickle.dumps(self_pub)
	#self_pub_len=struct.pack("=L",len(encd_self_pub))
	#pub_key_len=struct.unpack("=L",Lib.stream_read_in(sock,4,step=4))[0]
	#pub_key=pickle.loads(Lib.stream_read_in(sock,pub_key_len))
	#sock.send(self_pub_len)
	#sock.send(encd_self_pub)
	#return (pub_key_len,pub_key)
	#"""	

def _login(sock:socket.socket,pub_key:any,encd_name:bytes,passkey:bytes):
	public_key=None
	private_key=None
	Lib.ed_send(sock,pub_key,encd_name)
	Lib.ed_send(sock,pub_key,passkey)
	flag=Lib.ed_recv(sock,private_key).decode()
	return flag
	
def _sha512(key):
	cla=hashlib.sha512()
	cla.update(key)
	return cla.hexdigest().encode()

def _shake(sock:socket.socket,address:tuple,flag:str):
	sock.connect(address)
	#s_public_key=_token_exchange(sock,public_key)[1]
	s_public_key=None
	Lib.ed_send(sock,s_public_key,flag.encode())
	return s_public_key
	
def main():
	public_key=None
	private_key=None
	print(INFO.project_name)
	print(INFO.build)
	branch_id=("0"*128).encode()
	file_index={}
	branch_index={}
	default_save_path=os.getcwd()
	con=input("v4/v6>>")
	if con in ["v4","IPv4","ipv4","4"]:
		AF=socket.AF_INET
	else:
		AF=socket.AF_INET6
	con=True
	saddr=input("server_addr>>")
	sport=int(input("server_port>>"))
	try:
		while con:
			name=input("usr_name>>").encode()
			if name!=b"":
				password=_sha512(maskpass.askpass(prompt="password>>",mask="#").encode())
				passkey=copy.deepcopy(password)
				with _make_sock(AF,saddr) as sock:
					sock.connect((saddr,sport))
					s_public_key=_token_exchange(sock,public_key)[1]
					Lib.ed_send(sock,s_public_key,content=b"key_confirm")
					flag=_login(sock,s_public_key,name,password)
					if flag=="T":
						break
					else:
						logger.warning("there's something wrong with your password/account")
			else:
				while True:
					os.system('cls')
					while True:
						name=input('new_usr_name>>').encode()
						with _make_sock(AF,saddr) as sock:
							s_public_key=_shake(sock,(saddr,sport),"name_test")
							Lib.ed_send(sock,s_public_key,name)
							if Lib.ed_recv(sock,private_key)==b"T":
								break
							else:
								logger.warning("DUPLICATE user name")
					password=input('your_password>>').encode()
					passkey=_sha512(password)
					with _make_sock(AF,saddr) as sock:
						s_public_key=_shake(sock,(saddr,sport),"new_usr")
						Lib.ed_send(sock,s_public_key,name)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.ed_send(sock,s_public_key,passkey)
							break
	except:
		traceback.print_exc()
		return None
	logger.debug("Enter service loop")
	while True:
		command=input("command>>")
		try:
			if command=="change_password":
				password=maskpass.askpass(prompt="new_password>>",mask="#").encode()
				if password==maskpass.askpass(prompt="new_password>>",mask="#").encode():
					with _make_sock(AF,saddr) as sock:
						s_public_key=_shake(sock,(saddr,sport),"reset_password")
						if _login(sock,s_public_key,name,passkey)=="T":
							Lib.ed_send(sock,s_public_key,name)
							Lib.ed_send(sock,s_public_key,_sha512(password))
							passkey=_sha512(password)
				else:
					logger.exception("The two passwords are DIFFERENT.")
			elif command=="view_branch":
				flag=False
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"view_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							logger.debug("receiving response from server...")
							branch_info=Lib.lp_ed_recv(sock,private_key)
							logger.info("OVER")
							flag=True
				if flag:
					branch_info=json.loads(branch_info)
					print("branch id:\n\r",branch_info[0])
					print("branch name:",branch_info[1])
					print("branch owner:",branch_info[2])
					print("executives:")
					for executive in branch_info[3]:
						print("",executive)
					cont=0
					file_index={}
					print("files:")
					for file_id in branch_info[4]:
						print("|_",cont,":",branch_info[4][file_id],sep='')
						print("| |_id:",file_id,sep='')
						file_index[cont]=file_id
						cont+=1
					cont=0
					branch_index={}
					print("forks:")
					for _branch_id in branch_info[5]:
						print("|_",cont,":",branch_info[5][_branch_id],sep='')
						print("| |_id:",_branch_id,sep='')
						branch_index[cont]=_branch_id
						cont+=1
					print("intro:")
					print(branch_info[6])
					print("father:")
					print(branch_info[7])
					if branch_info[8]!="":
						print("mount_on:",branch_info[8])
				else:
					logger.critical("wrong branch id/bad network")
			elif command=="grow_branch":
				branch_name=input("branch_name>>").encode()
				intro_path=input("intro_path>>")
				introduction=None
				if os.path.exists(intro_path) and os.path.isfile(intro_path):
					with open(intro_path,"br") as f:
						introduction=f.read()
				else:
					logger.critical("NO such file")
					continue
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"grow_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,name)
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							if Lib.ed_recv(sock,private_key)==b"T":
								Lib.ed_send(sock,s_public_key,branch_name)
								Lib.ed_send(sock,s_public_key,introduction)
								print("new_branch:",Lib.ed_recv(sock,private_key).decode(),sep="")
							else:
								logger.critical("network error")
						else:
							logger.critical("no such branch")
			elif command=="cut_branch":
				cut_branch_id=input("id>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"cut_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,name)
						Lib.ed_send(sock,s_public_key,branch_id)
						Lib.ed_send(sock,s_public_key,cut_branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"V":
									logger.info("The branch was successfully removed")
								else:
									logger.error("unable to remove the branch")
							else:
								logger.critical("The requested slave branch does not exist")
						else:
							logger.critical("No such branch/No access to this branch")
			elif command=="add_branch_executive":
				new_executive=input("usrname>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"add_branch_executive")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.ed_send(sock,s_public_key,name)
							Lib.ed_send(sock,s_public_key,new_executive)
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"V":
									logger.info("The executive was successfully added")
								else:
									logger.error("unable to add executive")
							else:
								logger.critical("The requested user does not exist")
						else:
							logger.critical("No such branch/No access to this branch")
			elif command=="del_branch_executive":
				del_executive=input("usrname>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"del_branch_executive")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.ed_send(sock,s_public_key,name)
							Lib.ed_send(sock,s_public_key,del_executive)
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"V":
									logger.info("The executive was successfully deleted")
								else:
									logger.error("unable to delete executive")
							else:
								logger.critical("The requested executive does not exist/No access to this branch")
						else:
							logger.critical("No such branch")
			elif command=="mount_branch":
				branch_id=input("branch_id>>").encode()
				path=input("mount_path>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"mount_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.c_send(sock,name)
						Lib.c_send(sock,branch_id)
						Lib.c_send(sock,path)
						if Lib.c_recv(sock)==b"T":
							logger.debug("successfully mounted a branch")
						else:
							logger.critical("no such branch/path OR no access")
			elif command=="hang_file":
				file_name=input("file_name>>")
				file_path=input("file_path>>")
				path=file_path+os.sep+file_name
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"hang_file")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.ed_send(sock,s_public_key,name)
							#Lib.ed_send(sock,s_public_key,branch_id)
							if Lib.ed_recv(sock,private_key)==b"T":
								Lib.ed_send(sock,s_public_key,file_name.encode())
								Lib.f_c_send(sock,s_public_key,path,file_name,step=2048*450)
							else:
								logger.critical("No access to this branch")
						else:
							logger.critical("No such branch")
			elif command=="hang_file_ff":
				folder_path=input("folder_path>>")
				for file_name in os.listdir(folder_path):
					path=folder_path+os.sep+file_name
					if os.path.isfile(path):
						with _make_sock(AF,saddr) as sock:
							s_public_key=_shake(sock,(saddr,sport),"hang_file")
							if _login(sock,s_public_key,name,passkey)=="T":
								Lib.ed_send(sock,s_public_key,branch_id)
								if Lib.ed_recv(sock,private_key)==b"T":
									Lib.ed_send(sock,s_public_key,name)
									#Lib.ed_send(sock,s_public_key,branch_id)
									if Lib.ed_recv(sock,private_key)==b"T":
										Lib.ed_send(sock,s_public_key,file_name.encode())
										Lib.f_c_send(sock,s_public_key,path,file_name,step=2048*500)
									else:
										logger.critical("No access to this branch")
								else:
									logger.critical("No such branch")
			elif command=="pick_file":
				file_id=input("file_id>>").encode()
				save_path=input("save_path>>")
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"pick_file")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,file_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.f_c_recv(sock,private_key,save_path)
						else:
							logger.critical("No such file/branch")
			elif command=="get_file":
				index=int(input("index>>"))
				file_id=file_index[index].encode()
				save_path=default_save_path
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"pick_file")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,file_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							Lib.f_c_recv(sock,private_key,save_path)
						else:
							logger.critical("No such file/branch")
			elif command=="cut_file":
				file_id=input("file_id>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"cut_file")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,name)
						Lib.ed_send(sock,s_public_key,file_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"V":
									logger.debug("successfully cut a file")
								else:
									logger.error("failed to cut the file")
							else:
								logger.critical("No access")
						else:
							logger.critical("No such file/branch")
			elif command=="CAB_send":
				path=input("path>>")
				Libo.folder_uploader(saddr,sport,AF,name,passkey,path,branch_id.decode())
			elif command=="CAB_recover":
				folder_id=input("folder_id>>")
				dcp_id=file_index[int(input("dcp_id>>"))]
				reflection_id=file_index[int(input("reflect_id>>"))]
				environ_id=file_index[int(input("environ_id>>"))]
				Libo.folder_downloader(saddr,sport,AF,name,passkey,folder_id,dcp_id,reflection_id,environ_id)
			elif command=="del_file":
				index=int(input("index>>"))
				file_id=file_index[index].encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"cut_file")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,name)
						Lib.ed_send(sock,s_public_key,file_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"V":
									logger.debug("successfully cut a file")
								else:
									logger.error("failed to cut the file")
							else:
								logger.critical("No access")
						else:
							logger.critical("No such file/branch")
			elif command=="clear_file":
				input("Press enter to continue.")
				for file_id_ in file_index:
					file_id=file_index[file_id_].encode()
					#file_id=file_index[index].encode()
					with _make_sock(AF,saddr) as sock:
						s_public_key=_shake(sock,(saddr,sport),"cut_file")
						if _login(sock,s_public_key,name,passkey)=="T":
							Lib.ed_send(sock,s_public_key,name)
							Lib.ed_send(sock,s_public_key,file_id)
							if Lib.ed_recv(sock,private_key)==b"T":
								if Lib.ed_recv(sock,private_key)==b"T":
									if Lib.ed_recv(sock,private_key)==b"V":
										logger.debug("successfully cut "+file_id.decode())
									else:
										logger.error("failed to cut the file")
								else:
									logger.critical("No access")
							else:
								logger.critical("No such file/branch")
			elif command=="change_acc_creatable":
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"change_acc_creatable")
					if _login(sock,s_public_key,name,passkey)=="T":
						response=Lib.ed_recv(sock,private_key).decode()
						logger.info("accc: "+response)
			elif command=="add_usr":
				new_usrname=input("usr_name>>").encode()
				default_password=input("password>>").encode()
				new_passkey=_sha512(default_password)
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"add_usr")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.common_deined_send(sock,new_usrname)
						Lib.common_deined_send(sock,new_passkey)
						if Lib.common_deined_recv(sock)==b"T":
							logger.debug("successfully added a usr")
						else:
							logger.warning("something wrong happend")
			elif command=="del_usr":
				del_usrname=input("usr_name>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"del_usr")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.common_deined_send(sock,del_usrname)
						if Lib.common_deined_recv(sock)==b"T":
							logger.debug("successfully deled a usr")
						else:
							logger.warning("something wrong happend")
			elif command=="ban_usr":
				ban_usrname=input("ban_usr_name>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"ban_usr")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.common_deined_send(sock,ban_usrname)
						if Lib.common_deined_recv(sock)==b"T":
							logger.debug("successfully banned a usr")
						else:
							logger.warning("something wrong happend")
			elif command=="unban_usr":
				unban_usrname=input("ban_usr_name>>").encode()
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"ban_usr")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.common_deined_send(sock,unban_usrname)
						if Lib.common_deined_recv(sock)==b"T":
							logger.debug("successfully unbanned a usr")
						else:
							logger.warning("something wrong happend")
			elif command=="back":
				branch_id=branch_info[7].encode()
				flag=False
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"view_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							logger.debug("receiving response from server...")
							branch_info=Lib.lp_ed_recv(sock,private_key)
							logger.info("OVER")
							flag=True
				if flag:
					branch_info=json.loads(branch_info)
					print("branch id:\n\r",branch_info[0])
					print("branch name:",branch_info[1])
					print("branch owner:",branch_info[2])
					print("executives:")
					for executive in branch_info[3]:
						print("",executive)
					cont=0
					file_index={}
					print("files:")
					for file_id in branch_info[4]:
						print("|_",cont,":",branch_info[4][file_id],sep='')
						print("| |_id:",file_id,sep='')
						file_index[cont]=file_id
						cont+=1
					cont=0
					branch_index={}
					print("forks:")
					for _branch_id in branch_info[5]:
						print("|_",cont,":",branch_info[5][_branch_id],sep='')
						print("| |_id:",_branch_id,sep='')
						branch_index[cont]=_branch_id
						cont+=1
					print("intro:")
					print(branch_info[6])
					print("father:")
					print(branch_info[7])
					if branch_info[8]!="":
						print("mount_on:",branch_info[8])
				else:
					logger.critical("wrong branch id/bad network")
			elif command=="default_save_path":
				print(default_save_path)
				default_save_path=input("save_path>>")
			elif command=="change_branch":
				branch_id=input("branch_id>>").encode()
				flag=False
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"view_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							logger.debug("receiving response from server...")
							branch_info=Lib.lp_ed_recv(sock,private_key)
							logger.info("OVER")
							flag=True
				if flag:
					branch_info=json.loads(branch_info)
					print("branch id:\n\r",branch_info[0])
					print("branch name:",branch_info[1])
					print("branch owner:",branch_info[2])
					print("executives:")
					for executive in branch_info[3]:
						print("",executive)
					cont=0
					file_index={}
					print("files:")
					for file_id in branch_info[4]:
						print("|_",cont,":",branch_info[4][file_id],sep='')
						print("| |_id:",file_id,sep='')
						file_index[cont]=file_id
						cont+=1
					cont=0
					branch_index={}
					print("forks:")
					for _branch_id in branch_info[5]:
						print("|_",cont,":",branch_info[5][_branch_id],sep='')
						print("| |_id:",_branch_id,sep='')
						branch_index[cont]=_branch_id
						cont+=1
					print("intro:")
					print(branch_info[6])
					print("father:")
					print(branch_info[7])
					if branch_info[8]!="":
						print("mount_on:",branch_info[8])
				else:
					logger.critical("wrong branch id/bad network")
			elif command=="enter_branch":
				branch_id=branch_index[int(input("index>>"))].encode()
				flag=False
				with _make_sock(AF,saddr) as sock:
					s_public_key=_shake(sock,(saddr,sport),"view_branch")
					if _login(sock,s_public_key,name,passkey)=="T":
						Lib.ed_send(sock,s_public_key,branch_id)
						if Lib.ed_recv(sock,private_key)==b"T":
							logger.debug("receiving response from server...")
							branch_info=Lib.lp_ed_recv(sock,private_key)
							logger.info("OVER")
							flag=True
				if flag:
					branch_info=json.loads(branch_info)
					print("branch id:\n\r",branch_info[0])
					print("branch name:",branch_info[1])
					print("branch owner:",branch_info[2])
					print("executives:")
					for executive in branch_info[3]:
						print("",executive)
					cont=0
					file_index={}
					print("files:")
					for file_id in branch_info[4]:
						print("|_",cont,":",branch_info[4][file_id],sep='')
						print("| |_id:",file_id,sep='')
						file_index[cont]=file_id
						cont+=1
					cont=0
					branch_index={}
					print("forks:")
					for _branch_id in branch_info[5]:
						print("|_",cont,":",branch_info[5][_branch_id],sep='')
						print("| |_id:",_branch_id,sep='')
						branch_index[cont]=_branch_id
						cont+=1
					print("intro:")
					print(branch_info[6])
					print("father:")
					print(branch_info[7])
					if branch_info[8]!="":
						print("mount_on:",branch_info[8])
				else:
					logger.critical("wrong branch id/bad network")
			elif command=="high_level_command":
				logger.warning("注意，此处输入的命令可能破坏程序自身稳态!")
				exec(input("#command>>>"))
			elif command=="cls":
				os.system("cls")
			elif command=="exit":
				os.system("cls")
				break
		except:
			traceback.print_exc()
#public_key,private_key=1145