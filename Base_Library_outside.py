import os
import json
import time
import random
import hashlib
import ssl
import socket
import traceback
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed

import Base_Library as Lib

private_key=None

def dir_checker(dcp:str):
	with open(dcp,'r') as f:
		past_exists=json.load(f)
	sign=True
	for root in past_exists:
		if sign:
			re=root
			sign=False
		if not os.path.exists(root):
			os.mkdir(root)
		else:
			if not os.path.isdir(root):
				os.mkdir(root)
	return re

def md5_getter(file_path:str):
	with open(file_path, "rb") as f:
		file_hash = hashlib.md5()
		while chunk := f.read(8192):
			file_hash.update(chunk)
		return file_hash.hexdigest()
	
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

"""
def _token_exchange(sock,self_pub):
	return (None,None)
	#encd_self_pub=pickle.dumps(self_pub)
	#self_pub_len=struct.pack("=L",len(encd_self_pub))
	#pub_key_len=struct.unpack("=L",Lib.stream_read_in(sock,4,step=4))[0]
	#pub_key=pickle.loads(Lib.stream_read_in(sock,pub_key_len))
	#sock.send(self_pub_len)
	#sock.send(encd_self_pub)
	#return (pub_key_len,pub_key)
"""

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

def ol_file_checker(path:str,dcp:str,folder_id:str):
	with open("ol_environ_file_book_"+folder_id+".json",'r')as f:
		environ=json.load(f)
	with open(dcp,'r') as f:
		past_exists=json.load(f)
	now_exists=past_exists
	move_to={}
	move_from={}
	for root,_,files in os.walk(path):
		if not root in past_exists:
			now_exists[root]={}
			for item in files:
				file_id=str(time.time())+"."+str(random.randint(10000,99999))
				now_exists[root][item]=file_id
				move_to[root+os.sep+item]=[file_id,True]
				environ[file_id]=md5_getter(root+os.sep+item)
			continue
		for item in files:
			if item in past_exists[root]:
				file_id=past_exists[root][item]
				if environ[file_id]!=md5_getter(root+os.sep+item):
					move_to[root+os.sep+item]=[file_id,False]
			else:
				file_id=str(time.time())+"."+str(random.randint(10000,99999))
				now_exists[root][item]=file_id
				move_to[root+os.sep+item]=[file_id,True]
				environ[file_id]=md5_getter(root+os.sep+item)
		for item in past_exists[root]:
			if not item in files:
				move_from[root+os.sep+item]=past_exists[root][item]
	with open(dcp,'w')as f:
		json.dump(now_exists,f)
	with open("ol_environ_file_book_"+folder_id+".json",'w')as f:
		json.dump(environ,f)
	return move_to,move_from

def online_file_output(ol_file_id:str,to_path:str,server_ip:str,server_port:int,usr_name:str,passkey:bytes,AF):
	file_id=ol_file_id
	save_path=to_path
	#passkey=_sha512(password.encode())
	try:
		with _make_sock(AF,server_ip) as sock:
			s_public_key=_shake(sock,(server_ip,server_port),"CAB_pick_file")
			if _login(sock,s_public_key,usr_name,passkey)=="T":
				Lib.ed_send(sock,s_public_key,file_id.encode())
				if Lib.ed_recv(sock,private_key)==b"T":
					Lib.f_c_recv(sock,private_key,save_path,CAB=True)
					return True
				else:
					logger.critical("No such file/branch")
	except:
		traceback.print_exc()
		return None
	else:
		return None

def online_file_input_new(from_path:str,file_id:str,server_ip:str,server_port:int,branch_id:str,usr_name:bytes,passkey:bytes,AF):
	file_name=from_path.split(os.sep)[-1]
	#passkey=_sha512(password.encode())
	path=from_path
	try:
		with _make_sock(AF,server_ip) as sock:
			s_public_key=_shake(sock,(server_ip,server_port),"CAB_hang_file")
			if _login(sock,s_public_key,usr_name,passkey)=="T":
				Lib.ed_send(sock,s_public_key,branch_id.encode())
				if Lib.ed_recv(sock,private_key)==b"T":
					Lib.ed_send(sock,s_public_key,usr_name)
					#Lib.ed_send(sock,s_public_key,branch_id)
					if Lib.ed_recv(sock,private_key)==b"T":
						Lib.ed_send(sock,s_public_key,file_name.encode())
						Lib.f_c_send(sock,s_public_key,path,file_name,step=2048*100)
						ol_file_id=Lib.ed_recv(sock,private_key,step=2048).decode()
						return (file_id,ol_file_id)
					else:
						logger.critical("No access to this branch")
				else:
					logger.critical("No such branch")
	except:
		traceback.print_exc()
		return None
	else:
		return None
	
"""
def online_file_input_refresh(from_path:str,file_id:str,ol_file_id_in:str,server_ip:str,server_port:int,branch_id:str,usr_name:str,password:str):
	#file_name=from_path.split(os.sep)[-1]
	passkey=_sha512(password.encode())
	path=from_path
	try:
		with _make_sock(socket.AF_INET) as sock:
			s_public_key=_shake(sock,(server_ip,server_port),"CAB_refresh_file")
			if _login(sock,s_public_key,usr_name.encode(),passkey)=="T":
				Lib.ed_send(sock,s_public_key,branch_id.encode())
				if Lib.ed_recv(sock,private_key)==b"T":
					Lib.ed_send(sock,s_public_key,usr_name.encode())
					Lib.ed_send(sock,s_public_key,ol_file_id_in.encode())
					if Lib.ed_recv(sock,private_key)==b"T":
						#Lib.ed_send(sock,s_public_key,file_name.encode())
						Lib.f_c_send(sock,s_public_key,path,step=2048*100)
						ol_file_id=Lib.ed_recv(sock,private_key,step=2048).decode()
						return (file_id,ol_file_id)
					else:
						logger.critical("No access to this branch/No such file")
				else:
					logger.critical("No such branch")
	except:
		traceback.print_exc()
		return None
	else:
		return None
"""

def folder_uploader(server_ip:str,server_port:int,AF,usr_name:bytes,passkey:bytes,path:str,branch_id:str):
	obj=hashlib.md5("jczzc2@github.com©".encode())
	obj.update(path.encode())
	folder_id=obj.hexdigest()
	#passkey=_sha512(password.encode())
	dcp="ol_dcp_"+folder_id+".json"
	reflection="ol_lc_"+folder_id+".json"
	environ="ol_environ_file_book_"+folder_id+".json"
	with open("ol_environ_file_book_"+folder_id+".json","w")as f:
		json.dump({},f)
	with open("ol_dcp_"+folder_id+".json","w")as f:
		json.dump({},f)
	with open("ol_lc_"+folder_id+".json","w")as f:
		json.dump({},f)
	with open(reflection)as f:
		reflect_list=json.load(f)
	move_to,move_from=ol_file_checker(path,dcp,folder_id)
	del move_from
	thread_list=[]
	with ThreadPoolExecutor(max_workers=4) as input_threadpool:
		for file_path in move_to:
			#to_path="files"+os.sep+move_to[file_path]+".bin"
			#task=input_threadpool.submit(copyfile,file_path,to_path)
			task=input_threadpool.submit(online_file_input_new,file_path,move_to[file_path][0],server_ip,server_port,branch_id,usr_name,passkey,AF)
			thread_list.append(task)
		for future in as_completed(thread_list):
			try:
				re=future.result()
				if re!=None:
					#print(re)
					reflect_list[re[0]]=re[1]
			except:
				traceback.print_exc()
	with open(reflection,"w")as f:
		json.dump(reflect_list,f)
	for file_name in [dcp,reflection,environ]:
		path=os.getcwd()+os.sep+file_name
		with _make_sock(AF,server_ip) as sock:
			s_public_key=_shake(sock,(server_ip,server_port),"hang_file")
			if _login(sock,s_public_key,usr_name,passkey)=="T":
				Lib.ed_send(sock,s_public_key,branch_id.encode())
				if Lib.ed_recv(sock,private_key)==b"T":
					Lib.ed_send(sock,s_public_key,usr_name)
					#Lib.ed_send(sock,s_public_key,branch_id)
					if Lib.ed_recv(sock,private_key)==b"T":
						Lib.ed_send(sock,s_public_key,file_name.encode())
						Lib.f_c_send(sock,s_public_key,path,file_name,step=2048*450)
					else:
						logger.critical("No access to this branch")
				else:
					logger.critical("No such branch")
		os.remove(file_name)

def folder_downloader(server_ip:str,server_port:int,AF,usr_name:bytes,passkey:bytes,folder_id:str,dcp_id:str,reflection_id:str,environ_id:str):
	#passkey=_sha512(password.encode())
	for file_id_ in [dcp_id,reflection_id,environ_id]:
		file_id=file_id_.encode()
		save_path=os.getcwd()
		with _make_sock(AF,server_ip) as sock:
			s_public_key=_shake(sock,(server_ip,server_port),"pick_file")
			if _login(sock,s_public_key,usr_name,passkey)=="T":
				Lib.ed_send(sock,s_public_key,file_id)
				if Lib.ed_recv(sock,private_key)==b"T":
					Lib.f_c_recv(sock,private_key,save_path)
				else:
					logger.critical("No such file/branch")
					raise IOError("failed to fetch configer")
	dcp="ol_dcp_"+folder_id+".json"
	reflection="ol_lc_"+folder_id+".json"
	with open(reflection)as f:
		reflect_list=json.load(f)
	path=dir_checker(dcp)
	move_to,move_from=ol_file_checker(path,dcp,folder_id)
	thread_list=[]
	with ThreadPoolExecutor(max_workers=3) as output_threadpool:
		for file_path in move_from:
			#source_path="files"+os.sep+move_from[file_path]+".bin"
			#task=output_threadpool.submit(copyfile,reflection[move_from[file_path]],move_from[file_path],)
			task=output_threadpool.submit(online_file_output,reflect_list[move_from[file_path]],file_path,server_ip,server_port,usr_name,passkey,AF)
			thread_list.append(task)
		for _ in as_completed(thread_list):
			pass