import random
import os

ran="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=[]\\;,./`~!@#$%^&*()_+{}|:<>?____________"

if __name__=="__main__":
	out=""
	for i in range(20):
		index=random.randint(0,len(ran)-1)
		out+=ran[index]
	print(out)
	os.system("pause")