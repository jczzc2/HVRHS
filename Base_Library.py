import socket
import struct
import json
import os
#import rsa
import tqdm
from loguru import logger
from func_timeout import func_set_timeout
#socket.setdefaulttimeout(5)

@func_set_timeout(10)
def stream_read_in(cli,length,step=768*768):
	cache=b''
	while not len(cache)==length:
		if (length-len(cache))<=step:
			cache+=cli.recv(length-len(cache))
		else:
			cache+=cli.recv(step)
		#print(cache)
	return cache

def split(long_message,public_key=None):
	sec=200
	messages=[long_message[i:i+sec] for i in range(0,len(long_message),sec)]
	encoded_messages=[]
	for i in messages:
		encoded_messages.append(i)
	#encoded_messages=pickle.dumps(encoded_messages)
	encoded_messages_len=struct.pack("=L",len(encoded_messages))
	return [encoded_messages_len,encoded_messages]

def stick(encoded_messages,private_key=None):
	#encoded_messages=pickle.loads(encoded_messages)
	encoded_long_message=b''
	for i in encoded_messages:
		#message=i
		encoded_long_message+=i
	#long_message=pickle.loads(encoded_long_message)
	return encoded_long_message

def branch_existance(branch_id:str):
	if os.path.exists(os.getcwd()+os.sep+"branches"+os.sep+branch_id+".json"):
		if os.path.isfile(os.getcwd()+os.sep+"branches"+os.sep+branch_id+".json"):
			return True
		else:
			return False
	else:
		return False

def load_branch(branch_id:str):
	path="branches"+os.sep+branch_id+".json"
	if branch_existance(branch_id):
		with open(path) as f:
			return json.load(f)
	else:
		raise IOError("branch not exists")

def dump_branch(branch_id:str,content:list):
	path="branches"+os.sep+branch_id+".json"
	with open(path,"w") as f:
		json.dump(content,f)

def cut_branch(branch_id:str):
	branch=load_branch(branch_id)
	for S_branch_id in branch[5]:
		cut_branch(S_branch_id)
	for S_branch_id in branch[5]:
		#os.system("del /Q \""+os.getcwd()+os.sep+"branches"+os.sep+S_branch_id+".json\"")
		try:
			os.remove(os.getcwd()+os.sep+"branches"+os.sep+S_branch_id+".json")
		except:
			logger.warning("unable to del "+S_branch_id)
		logger.info("remove "+S_branch_id)
	for file_id in branch[4]:
		if branch[8]=="":
			mount_path=os.getcwd()+os.sep+"files"
		else:
			mount_path=branch[8]
		try:
			os.remove(mount_path+os.sep+file_id+".bin")
		except:
			logger.warning("unable to del "+file_id)
		logger.info("remove "+file_id)

def lp_ed_send(sock,content,pub=None):
	messages=split(content,pub)[1]
	encrypted_deined_send(sock,pub,str(len(messages)).encode())
	for item in messages:
		common_deined_send(sock,item)
		
def lp_ed_recv(sock,priv=None):
	cache=[]
	lenth=int(encrypted_deined_recv(sock,priv).decode())
	for _ in range(lenth):
		cache.append(common_deined_recv(sock,step=1024))
	return stick(cache,priv)

lp_c_send=lp_ed_send
lp_c_recv=lp_ed_recv

def f_c_send(sock:socket.socket,pub:any,file_path:str,file_name:str,step:int=768):
	file_size=os.path.getsize(file_path)
	if file_size%step!=0:
		piece_num=(file_size//step)+1
	else:
		piece_num=file_size//step
	piece_num=str(piece_num).encode()
	#encrypted_deined_send(sock,pub,str(step).encode())
	encrypted_deined_send(sock,pub,piece_num)
	piece_num=int(piece_num.decode())
	with open(file_path,"br") as f:
		for i in tqdm.tqdm(range(piece_num)):
			cache=f.read(step)
			common_deined_send(sock,cache)
			
def f_c_recv(sock:socket.socket,priv:any,save_path:str,CAB:bool=False):
	file_name=encrypted_deined_recv(sock,priv).decode()
	piece_num=encrypted_deined_recv(sock,priv)
	piece_num=int(piece_num.decode())
	if CAB:
		path=save_path
	else:
		path=save_path+os.sep+file_name
	with open(path,"bw") as f:
		for _ in tqdm.tqdm(range(piece_num)):
			cache=common_deined_recv(sock,step=2048*450)
			f.write(cache)

def f_s_send(sock:socket.socket,pub:any,file_id:str,branch:list,step:int=768):
	if branch[4]=="":
		file_path=os.getcwd()+os.sep+"files"+os.sep+file_id+".bin"
	else:
		file_path=branch[8]+os.sep+file_id+".bin"
	branch_id=file_id[:128]
	branch=load_branch(branch_id)
	file_name=branch[4][file_id].encode()
	file_size=os.path.getsize(file_path)
	if file_size%step!=0:
		piece_num=(file_size//step)+1
	else:
		piece_num=file_size//step
	piece_num=str(piece_num).encode()
	#encrypted_deined_send(sock,pub,str(step).encode())
	encrypted_deined_send(sock,pub,file_name)
	encrypted_deined_send(sock,pub,piece_num)
	piece_num=int(piece_num.decode())
	with open(file_path,"br") as f:
		for i in range(piece_num):
			cache=f.read(step)
			common_deined_send(sock,cache)

def get_file_size(file_id:str):
	branch_id=file_id[:128]
	if file_existance(branch_id):
		branch=load_branch(branch_id)
		if branch[4]=="":
			file_path=os.getcwd()+os.sep+"files"+os.sep+file_id+".bin"
		else:
			file_path=branch[8]+os.sep+file_id+".bin"
		return os.path.getsize(file_path)
	else:
		return None

def p_f_s_send(sock:socket.socket,file_id:str,inition:"int>=0",length:int,branch:list,step:int):
	st_ed=inition+length
	if branch[4]=="":
		file_path=os.getcwd()+os.sep+"files"+os.sep+file_id+".bin"
	else:
		file_path=branch[8]+os.sep+file_id+".bin"
	file_size=os.path.getsize(file_path)
	if st_ed>=file_size:
		end_size=file_size-inition
	else:
		end_size=length
	if end_size%step!=0:
		piece_num=(end_size//step)+1
		flag=True
	else:
		piece_num=end_size//step
		flag=False
	piece_num=str(piece_num).encode()
	common_deined_send(sock,piece_num)
	piece_num=int(piece_num.decode())
	with open(file_path,"br") as f:
		for i in range(piece_num):
			if i==piece_num-1 and flag:
				cache=f.read(end_size%step)
				common_deined_send(sock,cache)
			else:
				cache=f.read(step)
				common_deined_send(sock,cache)

def p_f_c_recv(sock:socket.socket,file_name:str,save_path:str):
	piece_num=common_deined_recv(sock)
	piece_num=int(piece_num.decode())
	with open(save_path+os.sep+file_name,"bw") as f:
		for i in range(piece_num):
			cache=common_deined_recv(sock,step=(2048*450))
			f.write(cache)

def f_s_recv(sock:socket.socket,priv:any,file_id:str,branch:list):
	if branch[4]=="":
		file_path=os.getcwd()+os.sep+"files"+os.sep+file_id+".bin"
	else:
		file_path=branch[8]+os.sep+file_id+".bin"
	piece_num=encrypted_deined_recv(sock,priv)
	piece_num=int(piece_num.decode())
	with open(file_path,"bw") as f:
		logger.debug("writting in "+file_path)
		for _ in range(piece_num):
			cache=common_deined_recv(sock,step=2048*450)
			f.write(cache)
			#f.flush()
		logger.debug("written in "+file_path)

def file_existance(file_id:str):
	branch_id=file_id[:128]
	logger.debug("testing "+branch_id)
	if branch_existance(branch_id):
		logger.debug("viewing "+branch_id)
		branch=load_branch(branch_id)
		if file_id in branch[4]:
			return True
		else:
			return False
	else:
		return False

def del_file(file_id:str):
	branch_id=file_id[:128]
	branch=load_branch(branch_id)
	#path="\""+os.getcwd()+os.sep+"files"+os.sep+file_id+".bin"+"\""
	if branch[8]=="":
		mount_path=os.getcwd()+os.sep+"files"
	else:
		mount_path=branch[8]
	try:
		os.remove(mount_path+os.sep+file_id+".bin")
	except:
		logger.warning("unable to del "+file_id)
	del branch[4][file_id]
	dump_branch(branch[0],branch)

"""
def encrypted_read_in(sock,length,priv,step=768):
	return rsa.decrypt(stream_read_in(sock,length,step),priv)

def encrypted_deined_send(sock,pub,content:bytes):
	ecd_content=rsa.encrypt(content,pub)
	length=struct.pack("=L",len(ecd_content))
	sock.send(length)
	sock.send(ecd_content)
	
def encrypted_deined_recv(sock,priv,step=768):
	length=struct.unpack("=L",stream_read_in(sock,4,step=4))[0]
	return encrypted_read_in(sock,length,priv,step=step)
"""

def encrypted_read_in(sock,length,priv,step=768):
	return stream_read_in(sock,length,step)

def encrypted_deined_send(sock,pub,content:bytes):
	length=struct.pack("=L",len(content))
	sock.send(length)
	sock.send(content)

def encrypted_deined_recv(sock,priv,step=768):
	length=struct.unpack("=L",stream_read_in(sock,4,step=4))[0]
	return stream_read_in(sock,length,step=step)
	
def common_deined_send(sock,content:bytes):
	length=struct.pack("=L",len(content))
	sock.send(length)
	sock.send(content)
	
def common_deined_recv(sock,step=768):
	length=struct.unpack("=L",stream_read_in(sock,4,step=4))[0]
	return stream_read_in(sock,length,step=step)

ecd_read=encrypted_read_in
sri=stream_read_in
ed_send=encrypted_deined_send
ed_recv=encrypted_deined_recv
c_send=common_deined_send
c_recv=common_deined_recv
b_exist=branch_existance