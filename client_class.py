from re import A
import socket
import pickle
import os
import time
import struct
import json
import _thread
import threading
import traceback
import hashlib
import maskpass
import copy
import rsa
import ssl
import Base_Library as Lib
import INFO
from loguru import logger

AF4=socket.AF_INET
AF6=socket.AF_INET6

socket.setdefaulttimeout(3600)

#feature functions
def _make_sock(AF):
	#ssl wraper
	CA_FILE="ca-cert.pem"
	SERVER_CERT_FILE="server-cert.pem"
	CLIENT_KEY_FILE="client-key.pem"
	CLIENT_CERT_FILE = "client-cert.pem"
	context=ssl.SSLContext(ssl.PROTOCOL_TLS)
	context.check_hostname = False
	context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
	context.load_verify_locations(CA_FILE)
	context.verify_mode = ssl.CERT_REQUIRED
	context.load_verify_locations(cafile=CA_FILE)
	sock=socket.socket(AF,socket.SOCK_STREAM)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	ssock=context.wrap_socket(sock, server_side=False)
	return ssock

def _token_exchange(sock,self_pub):
	#wasted
	encd_self_pub=pickle.dumps(self_pub)
	self_pub_len=struct.pack("=L",len(encd_self_pub))
	pub_key_len=struct.unpack("=L",Lib.stream_read_in(sock,4,step=4))[0]
	pub_key=pickle.loads(Lib.stream_read_in(sock,pub_key_len))
	sock.send(self_pub_len)
	sock.send(encd_self_pub)
	return (pub_key_len,pub_key)

def _login(sock:socket.socket,pub_key:rsa.PublicKey,encd_name:bytes,passkey:bytes):
	Lib.ed_send(sock,pub_key,encd_name)
	Lib.ed_send(sock,pub_key,passkey)
	flag=Lib.ed_recv(sock,None).decode()
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

#errors
class AccountExceptionError(Exception):
	pass

class UnknownError(Exception):
	pass

class BranchNotFoundError(Exception):
	pass

#protocol
class man:
	def __init__(self,protocol:str):
		match protocol:
			case "AF_INET":
				self.protocol=AF4
			case "AF4":
				self.protocol=AF4
			case "AF_INET6":
				self.protocol=AF6
			case "AF6":
				self.protocol=AF6
			case _:
				raise Exception("wrong argu "+protocol)

#class client
class client:
	def __init__(self,server_ip:str,port:int,protocol:man,name:str,password:str):
		self.password=_sha512(maskpass.askpass(prompt="password>>",mask="#").encode())
		self.passkey=self.password
		self.addr=server_ip
		self.port=port
		self.protocol=protocol.protocol
		self.branch_id="0"*128
		self.public_key=None
		self.private_key=None
		self.branch_info=[]
		
	def shake(self):
		with _make_sock(self.protocol) as sock:
			sock.connect((self.addr,self.port))
			s_public_key=_token_exchange(sock,self.public_key)[1]
			Lib.ed_send(sock,s_public_key,content=b"key_confirm")
			flag=_login(sock,s_public_key,self.name,self.password)
			if flag=="T":
				return True
			else:
				logger.warning("there's something wrong with your password/account")
				raise AccountExceptionError("Wrong Account/Error in login")
	
	def branchoutput(self,branch_info:list):
		print("branch id:\n\r",branch_info[0])
		print("branch name:",branch_info[1])
		print("branch owner:",branch_info[2])
		print("executives:")
		for executive in branch_info[3]:
			print("",executive)
		print("files:")
		for file_id in branch_info[4]:
			print("|_",branch_info[4][file_id],sep='')
			print("| |_id:",file_id,sep='')
		print("forks:")
		for _branch_id in branch_info[5]:
			print("|_",branch_info[5][_branch_id],sep='')
			print("| |_id:",_branch_id,sep='')
		print("intro:")
		print(branch_info[6])

	def viewbranch(self,output:bool=False):
		flag=False
		with _make_sock(self.protocol) as sock:
			s_public_key=_shake(sock,(self.addr,self.port),"view_branch")
			if _login(sock,s_public_key,self.name,self.passkey)=="T":
				Lib.ed_send(sock,s_public_key,self.branch_id)
				if Lib.ed_recv(sock,self.private_key)==b"T":
					logger.debug("receiving response from server...")
					branch_info=Lib.lp_ed_recv(sock,self.private_key)
					logger.info("OVER")
					flag=True
			else:
				raise AccountExceptionError
		if flag and output:
			branch_info=json.loads(branch_info)
			self.branchoutput(branch_info)
			self.branch_info=branch_info
			return branch_info
		elif flag:
			branch_info=json.loads(branch_info)
			self.branch_info=branch_info
			return branch_info
		else:
			#logger.critical("wrong branch id/bad network")
			raise UnknownError("wrong branch id/bad network")
		
	def growbranch(self,pre_branch_name:str,intro_path:str):
		branch_name=pre_branch_name.encode()
		introduction=None
		if os.path.exists(intro_path) and os.path.isfile(intro_path):
			with open(intro_path,"br") as f:
				introduction=f.read()
		else:
			#logger.critical("NO such file")
			raise FileNotFoundError("no such file")
		with _make_sock(self.protocol) as sock:
			s_public_key=_shake(sock,(self.addr,self.port),"grow_branch")
			if _login(sock,s_public_key,self.name,self.password)=="T":
				Lib.ed_send(sock,s_public_key,self.name)
				Lib.ed_send(sock,s_public_key,self.branch_id)
				if Lib.ed_recv(sock,self.private_key)==b"T":
					if Lib.ed_recv(sock,self.private_key)==b"T":
						Lib.ed_send(sock,s_public_key,branch_name)
						Lib.ed_send(sock,s_public_key,introduction)
						self.branch_id=Lib.ed_recv(sock,self.private_key)
					else:
						#logger.critical("network error")
						raise UnknownError
				else:
					#logger.critical("no such branch")
					raise BranchNotFoundError
				
	def cutbranch(self,cut_branch_id:str):
		with _make_sock(self.protocol) as sock:
			s_public_key=_shake(sock,(self.addr,self.port),"cut_branch")
			if _login(sock,s_public_key,self.name,self.passkey)=="T":
				Lib.ed_send(sock,s_public_key,self.branch_id)
				Lib.ed_send(sock,s_public_key,cut_branch_id)
				if Lib.ed_recv(sock,None)==b"T":
					if Lib.ed_recv(sock,None)==b"T":
						if Lib.ed_recv(sock,None)==b"V":
							logger.info("The branch was successfully removed")
						else:
							logger.error("unable to remove the branch")
							raise UnknownError("There were some problems when deleting the branch, but it doesn't seem to be a client error")
					else:
						logger.critical("The requested slave branch does not exist")
						raise BranchNotFoundError
				else:
					raise AccountExceptionError("no access")
			else:
				raise AccountExceptionError("Account Error")
	
	def hangfile(self,path:str,logname:str):
		file_name=logname
		#file_path=input("file_path>>")
		#path=file_path+os.sep+file_name
		with _make_sock(self.protocol) as sock:
			s_public_key=_shake(sock,(self.addr,self.port),"hang_file")
			if _login(sock,s_public_key,self.name,self.passkey)=="T":
				Lib.ed_send(sock,s_public_key,self.branch_id)
				if Lib.ed_recv(sock,None)==b"T":
					Lib.ed_send(sock,s_public_key,self.name)
					#Lib.ed_send(sock,s_public_key,branch_id)
					if Lib.ed_recv(sock,None)==b"T":
						Lib.ed_send(sock,s_public_key,file_name.encode())
						Lib.f_c_send(sock,s_public_key,path,file_name,step=2048*450)
					else:
						#logger.critical("No access to this branch")
						raise AccountExceptionError("no_access")
				else:
					#logger.critical("No such branch")
					raise BranchNotFoundError
			else:
				raise AccountExceptionError("wrong account")
			