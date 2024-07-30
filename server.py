import socket
import pickle
import os
import time
import struct
import json
import _thread
import threading
import traceback
import random
import ssl
#import maskpass
import hashlib
#import rsa
#from rsa import key
#import sys
import INFO
import Base_Library as Lib
from loguru import logger
#import func_timeout
socket.setdefaulttimeout(1800)
high_risk_account=False

def _waiters_manager():
	global waiters
	global public_key,private_key,encoded_public_key,encoded_public_key_len
	logger.debug("manager start")
	#token_change_sign=time.time()
	#token_change_time=0
	#key_changed=True
	report_sign=time.time()
	while True:
		cont=0
		bre=False
		lock.acquire()
		if time.time()-report_sign>=20:
			report_sign=time.time()
			logger.debug("existing threads:"+str(len(waiters)))
		for waiter in waiters:
			if not waiter.is_alive():
				del waiters[cont]
				logger.debug("existing threads:"+str(len(waiters)))
				bre=True
				break
			cont+=1
		lock.release()
		"""
		if key_changed and len(waiters)==0:
			logger.debug("making keys")
			public_key_1,private_key_1=rsa.newkeys(2048)
			encoded_public_key_1=pickle.dumps(public_key_1)
			encoded_public_key_len_1=struct.pack("=L",len(encoded_public_key_1))
			key_changed=False 
			logger.debug("new keys ready")
		"""
		if not bre:
			event=threading.Event()
			event.wait(10)

def _token_exchange(sock,self_pub):
	encd_self_pub=pickle.dumps(self_pub)
	self_pub_len=struct.pack("=L",len(encd_self_pub))
	sock.send(self_pub_len)
	sock.send(encd_self_pub)
	pub_key_len=struct.unpack("=L",Lib.stream_read_in(sock,4,step=4))[0]
	pub_key=pickle.loads(Lib.stream_read_in(sock,pub_key_len))
	return (pub_key_len,pub_key)

def _login_config(sock,pub):
	name=Lib.ed_recv(sock,private_key).decode()
	key=Lib.ed_recv(sock,private_key).decode()
	with lock_acc:
		if (name in names) and (not name in banned_list):
			if key==key_chain[name] and (not name in banned_list):
				Lib.ed_send(sock,pub,b"T")
				return True
			else:
				Lib.ed_send(sock,pub,b"F")
		else:
			Lib.ed_send(sock,pub,b"F")
		return False

def _admin_login_config(sock,pub):
	name=Lib.ed_recv(sock,private_key).decode()
	key=Lib.ed_recv(sock,private_key).decode()
	with lock_acc:
		if name in names:
			if key==key_chain[name] and (name in admin):
				Lib.ed_send(sock,pub,b"T")
				return True
			else:
				Lib.ed_send(sock,pub,b"F")
		else:
			Lib.ed_send(sock,pub,b"F")
		return False

def _sha512(key):
	cla=hashlib.sha512()
	cla.update(key)
	return cla.hexdigest()

def _sever(s):
	while True:
		try:
			_client(s)
		except:
			traceback.print_exc()

def _client(s):
	while True:
		try:
			c,addr=s.accept()
		except TimeoutError:
			continue
		except:
			traceback.print_exc()
			continue
		c.settimeout(10)
		c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,True)
		waiter=threading.Thread(target=_handler,args=(c,addr))
		del c
		waiter.start()
		waiters.append(waiter)

def main():
	CA_FILE="ca-cert.pem"
	KEY_FILE="server-key.pem"
	CERT_FILE="server-cert.pem"
	context=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
	context.load_verify_locations(CA_FILE)
	context.verify_mode = ssl.CERT_REQUIRED
	context.check_hostname = False
	with open('address.json') as f:
		address=json.load(f)
		if not ":" in address:
			s=socket.socket()
		else:
			s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
		s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		ss=context.wrap_socket(s, server_side=True)
		ss.settimeout(30)
		ss.bind((address,8192))
		ss.listen(100000)
		a=_thread.start_new_thread(_sever,(ss,))
	manager=threading.Thread(target=_waiters_manager,args=())
	manager.start()
	while True:pass

def _handler(sock,addr):
	global names
	global key_chain
	global account_creatable
	global public_key
	global private_key
	global banned_list
	with lock:
		logger.info(str(addr)+" connected")
	with sock:
		#c_public_key=_token_exchange(sock,public_key)[1]
		c_public_key=None
		command=Lib.ed_recv(sock,private_key).decode()
		if command=="key_confirm":
			_login_config(sock,c_public_key)
		elif command=="name_test":
			name=Lib.ed_recv(sock,private_key).decode()
			if name in names:
				Lib.ed_send(sock,c_public_key,b'F')
			else:
				Lib.ed_send(sock,c_public_key,b'T')
		elif command=="new_usr":
			name=Lib.ed_recv(sock,private_key).decode()
			with lock_acc:
				if (not name in names) and account_creatable:
					Lib.ed_send(sock,c_public_key,b"T")
					passkey=Lib.ed_recv(sock,private_key).decode()
					names.append(name)
					key_chain[name]=passkey
					with open("names.json","w") as f:
						json.dump(names,f)
					with open('passwords.json',"w") as f:
						json.dump(key_chain,f)
				else:
					Lib.ed_send(sock,c_public_key,b'F')
		elif command=="grow_branch":
			if _login_config(sock,c_public_key):
				name=Lib.ed_recv(sock,private_key).decode()
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					father=Lib.load_branch(branch_id)
					if (name in father[3]) or (name==father[2]):
						Lib.ed_send(sock,c_public_key,b"T")
						new_branch_name=Lib.ed_recv(sock,private_key).decode()
						new_branch_intro=Lib.ed_recv(sock,private_key).decode()
						b_time=str(time.time()).encode()
						b_rand=str(random.randint(100000000,999999999)).encode()
						new_branch_id=_sha512(new_branch_name.encode()+b_time+b_rand)
						sign=False
						for i in range(10):
							if Lib.branch_existance(new_branch_id):
								new_branch_id=_sha512(new_branch_name.encode()+b_time+b_rand)
								sign=True
								break
							else:
								continue
						if sign:
							sock.close()
							return None
						branch=[new_branch_id,new_branch_name,name,father[3],{},{},new_branch_intro,branch_id,father[8]]
						father[5][new_branch_id]=new_branch_name
						with lock_branch:
							Lib.dump_branch(branch_id,father)
							Lib.dump_branch(new_branch_id,branch)
						Lib.ed_send(sock,c_public_key,new_branch_id.encode())
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="cut_branch":
			if _login_config(sock,c_public_key):
				name=Lib.ed_recv(sock,private_key).decode()
				branch_id=Lib.ed_recv(sock,private_key).decode()
				cut_branch_id=Lib.ed_recv(sock,private_key).decode()
				path=os.getcwd()+os.sep+"branches"+os.sep+branch_id+".json"
				if Lib.b_exist(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					with lock_branch:
						father=Lib.load_branch(branch_id)
					if (cut_branch_id in father[5]) and ((name in father[3]) or (name==father[2])):
						Lib.ed_send(sock,c_public_key,b"T")
						#Lib.cut_branch(cut_branch_id)
						#os.system("del /Q \""+os.getcwd()+os.sep+"branches"+os.sep+cut_branch_id+".json\"")
						with lock_branch:
							Lib.cut_branch(cut_branch_id)
							try:
								os.remove(os.getcwd()+os.sep+"branches"+os.sep+cut_branch_id+".json")
							except:
								Lib.ed_send(sock,c_public_key,b"F")
								return 0
							#Lib.cut_branch(cut_branch_id)
							del father[5][cut_branch_id]
							try:
								Lib.dump_branch(branch_id,father)
								Lib.ed_send(sock,c_public_key,b"V")
							except:
								Lib.ed_send(sock,c_public_key,b"F")
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="clone_branch":
			if _login_config(sock,c_public_key):
				pass
		elif command=="change_intro":
			if _login_config(sock,c_public_key):
				pass
		elif command=="view_branch":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				path=os.getcwd()+os.sep+"branches"+os.sep+branch_id+".json"
				if os.path.exists(path) and os.path.isfile(path):
					Lib.ed_send(sock,c_public_key,b"T")
					logger.debug(str(addr)+" viewed "+branch_id)
					with open("branches"+os.sep+branch_id+".json","br") as f:
						branch_info=f.read()
					Lib.lp_ed_send(sock,branch_info,c_public_key)
				else:
					logger.debug(str(addr)+" viewed wrong branch "+branch_id)
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="add_branch_executive":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					usr_name=Lib.ed_recv(sock,private_key).decode()
					new_executive=Lib.ed_recv(sock,private_key).decode()
					with lock_branch:
						branch=Lib.load_branch(branch_id)
						if usr_name==branch[2] and (new_executive in names):
							Lib.ed_send(sock,c_public_key,b"T")
							executives=set(branch[3])
							executives.add(new_executive)
							executives=list(executives)
							branch[3]=executives
							try:
								Lib.dump_branch(branch_id,branch)
								Lib.ed_send(sock,c_public_key,b"V")
							except:
								Lib.ed_send(sock,c_public_key,b"F")
						else:
							Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="del_branch_executive":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					usr_name=Lib.ed_recv(sock,private_key).decode()
					del_executive=Lib.ed_recv(sock,private_key).decode()
					with lock_branch:
						branch=Lib.load_branch(branch_id)
						if usr_name==branch[2] and (del_executive in branch[3]):
							Lib.ed_send(sock,c_public_key,b"T")
							executives=set(branch[3])
							executives.remove(del_executive)
							executives=list(executives)
							branch[3]=executives
							try:
								Lib.dump_branch(branch_id,branch)
								Lib.ed_send(sock,c_public_key,b"V")
							except:
								Lib.ed_send(sock,c_public_key,b"F")
						else:
							Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="mount_branch":
			if _admin_login_config(sock,None):
				name=Lib.c_recv(sock).decode()
				branch_id=Lib.c_recv(sock).decode()
				mount_path=Lib.c_recv(sock).decode()
				if Lib.branch_existance(branch_id) and os.path.exists(mount_path):
					with lock_branch:
						branch=Lib.load_branch(branch_id)
					if len(branch[4])<=0 and name==branch[2] and os.path.isdir(mount_path):
						branch[8]=mount_path
						with lock_branch:
							Lib.dump_branch(branch_id,branch)
						Lib.c_send(sock,b"T")
					else:
						Lib.c_send(sock,b"F")
				else:
					Lib.c_send(sock,b"F")
		elif command=="hang_file":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					name=Lib.ed_recv(sock,private_key).decode()
					with lock_branch:
						branch=Lib.load_branch(branch_id)
					if name==branch[2] or (name in branch[3]):
						Lib.ed_send(sock,c_public_key,b"T")
						file_name=Lib.ed_recv(sock,private_key).decode()
						file_id=branch[0]+"."+str(round(time.time(),3))
						Lib.f_s_recv(sock,private_key,file_id,branch)
						with lock_branch:
							branch=Lib.load_branch(branch_id)
							branch[4][file_id]=file_name
							Lib.dump_branch(branch[0],branch)
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="pick_file":
			if _login_config(sock,c_public_key):
				file_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.file_existance(file_id):
					branch_id=file_id.split(".")[0]
					with lock_branch:
						branch=Lib.load_branch(branch_id)
					Lib.ed_send(sock,c_public_key,b"T")
					Lib.f_s_send(sock,c_public_key,file_id,branch,step=2048*450)
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="get_file_size":
			file_id=Lib.c_recv(sock).decode()
			file_size=Lib.get_file_size(file_id)
			if file_size!=None:
				Lib.c_send(sock,b"T")
				Lib.c_send(sock,str(file_size).encode())
			else:
				Lib.c_send(sock,b"F")
		elif command=="pick_file_piece":
			file_id=Lib.c_recv(sock).decode()
			if Lib.file_existance(file_id):
				Lib.c_send(sock,b"T")
				inition=int(Lib.c_recv(sock).decode())
				length=int(Lib.c_recv(sock).decode())
				with lock_branch:
					branch=Lib.load_branch(file_id[:128])
				Lib.p_f_s_send(sock,file_id,inition,length,branch,step=2048*500)
			else:
				Lib.c_send(sock,b"F")
		elif command=="CAB_hang_file":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					name=Lib.ed_recv(sock,private_key).decode()
					with lock_branch_CAB:
						branch=Lib.load_branch(branch_id)
					if name==branch[2] or (name in branch[3]):
						Lib.ed_send(sock,c_public_key,b"T")
						file_name=Lib.ed_recv(sock,private_key).decode()
						file_id=branch[0]+"."+str(round(time.time(),3))
						Lib.f_s_recv(sock,private_key,file_id,branch)
						Lib.ed_send(sock,c_public_key,file_id.encode())
						with lock:
							branch=Lib.load_branch(branch_id)
							branch[4][file_id]=file_name
							Lib.dump_branch(branch[0],branch)
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="CAB_refresh_file":
			if _login_config(sock,c_public_key):
				branch_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.branch_existance(branch_id):
					Lib.ed_send(sock,c_public_key,b"T")
					name=Lib.ed_recv(sock,private_key).decode()
					file_id=Lib.ed_recv(sock,private_key).decode()
					with lock_branch_CAB:
						branch=Lib.load_branch(branch_id)
					if (name==branch[2] or (name in branch[3])) and (file_id in branch[4]):
						Lib.ed_send(sock,c_public_key,b"T")
						#file_name=Lib.ed_recv(sock,private_key).decode()
						#file_id=branch[0]+"."+str(round(time.time(),3))
						Lib.f_s_recv(sock,private_key,file_id,branch)
						Lib.ed_send(sock,c_public_key,file_id.encode())
						"""
						branch=Lib.load_branch(branch_id)
						branch[4][file_id]=file_name
						Lib.dump_branch(branch[0],branch)
						"""
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="CAB_pick_file":
			if _login_config(sock,c_public_key):
				file_id=Lib.ed_recv(sock,private_key).decode()
				with lock_branch_CAB:
					control=Lib.file_existance(file_id)
				if control:
					branch_id=file_id.split(".")[0]
					with lock_branch:
						branch=Lib.load_branch(branch_id)
					Lib.ed_send(sock,c_public_key,b"T")
					Lib.f_s_send(sock,c_public_key,file_id,branch,step=2048*150)
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="cut_file":
			if _login_config(sock,c_public_key):
				name=Lib.ed_recv(sock,private_key).decode()
				file_id=Lib.ed_recv(sock,private_key).decode()
				if Lib.file_existance(file_id):
					Lib.ed_send(sock,c_public_key,b"T")
					with lock_branch:
						branch=Lib.load_branch(file_id[:128])
					if name==branch[2] or (name in branch[3]):
						Lib.ed_send(sock,c_public_key,b"T")
						try:
							Lib.ed_send(sock,c_public_key,b"V")
							with lock_file:
								with lock_branch:
									Lib.del_file(file_id)
							logger.debug(file_id+" been cut")
						except:
							traceback.print_exc()
							Lib.ed_send(sock,c_public_key,b"F")
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				else:
					Lib.ed_send(sock,c_public_key,b"F")
		elif command=="reset_password":
			if _login_config(sock,c_public_key):
				name=Lib.ed_recv(sock,private_key).decode()
				passkey=Lib.ed_recv(sock,private_key).decode()
				with lock_acc:
					key_chain[name]=passkey
					with open('passwords.json',"w") as f:
						json.dump(key_chain,f)
		elif command=="change_acc_creatable":
			if _admin_login_config(sock,c_public_key):
				account_creatable=not account_creatable
				if account_creatable:
					Lib.ed_send(sock,c_public_key,b"True")
				else:
					Lib.ed_send(sock,c_public_key,b"False")
				with open("acc_creatable.json",'w') as f:
					json.dump(account_creatable,f)
		elif command=="add_usr":
			if _admin_login_config(sock,c_public_key):
				usr_name=Lib.ed_recv(sock,private_key).decode()
				default_password=Lib.ed_recv(sock,private_key).decode()
				with lock_acc:
					if not usr_name in names:
						Lib.ed_send(sock,c_public_key,b"T")
						#high_risk_account=True
						_names=set(names)
						_names.add(usr_name)
						names=list(_names)
						key_chain[usr_name]=default_password
						with open("passwords.json","w") as f:
							json.dump(key_chain,f)
						with open("names.json","w") as f:
							json.dump(names,f)
						#high_risk_account=False
						del _names
					else:
						Lib.ed_send(sock,c_public_key,b"F")
		elif command=="del_usr":
			if _admin_login_config(sock,c_public_key):
				usr_name=Lib.ed_recv(sock,private_key).decode()
				with lock_acc:
					if (usr_name in names) and (not usr_name in admin):
						Lib.ed_send(sock,c_public_key,b"T")
						#high_risk_account=True
						_names=set(names)
						_names.remove(usr_name)
						names=list(_names)
						del key_chain[usr_name]
						with lock_ban:
							if usr_name in banned_list:
								_banned_list=set(banned_list)
								_banned_list.remove(usr_name)
								banned_list=list(_banned_list)
								del _banned_list
								with open("banned.json","w") as f:
									json.dump(banned_list,f)
						with open("passwords.json","w") as f:
							json.dump(key_chain,f)
						with open("names.json","w") as f:
							json.dump(names,f)
						#high_risk_account=False
						del _names
					else:
						Lib.ed_send(sock,c_public_key,b"F")
		elif command=="ban_usr":
			if _admin_login_config(sock,c_public_key):
				usr_name=Lib.ed_recv(sock,private_key).decode()
				with lock_ban:
					if (usr_name in names) and (not usr_name in admin):
						#high_risk_account=True
						_banned_list=set(banned_list)
						_banned_list.add(usr_name)
						banned_list=list(_banned_list)
						del _banned_list
						with open("banned.json","w") as f:
							json.dump(banned_list,f)
						Lib.ed_send(sock,c_public_key,b"T")
					else:
						Lib.ed_send(sock,c_public_key,b"F")
		elif command=="unban_usr":
			if _admin_login_config(sock,c_public_key):
				usr_name=Lib.ed_recv(sock,private_key).decode()
				with lock_ban:
					if (usr_name in names) and (usr_name in banned_list):
						#high_risk_account=True
						_banned_list=set(banned_list)
						_banned_list.remove(usr_name)
						banned_list=list(_banned_list)
						del _banned_list
						with open("banned.json","w") as f:
							json.dump(banned_list,f)
						Lib.ed_send(sock,c_public_key,b"T")
					else:
						Lib.ed_send(sock,c_public_key,b"F")
				
			   
lock=None
lock = threading.Lock()
lock_branch=threading.Lock()
lock_branch_CAB=threading.Lock()
lock_acc=threading.Lock()
lock_file=threading.Lock()
lock_ban=threading.Lock()
waiters=[]
"""
public_key,private_key=rsa.newkeys(2048)
encoded_public_key=pickle.dumps(public_key)
encoded_public_key_len=struct.pack("=L",len(encoded_public_key))
"""
encoded_public_key,encoded_public_key_len,public_key,private_key="Nan_"
encoded_public_key_len=0
account_creatable=True
logger.info("server init")
with open('admins.json')as f:
	admin=json.load(f)
with open('names.json','r') as f:
	names=json.load(f)
with open('passwords.json','r') as f:
	key_chain=json.load(f)
with open('banned.json','r') as f:
	banned_list=json.load(f)
with open("acc_creatable.json")as f:
	account_creatable=json.load(f)