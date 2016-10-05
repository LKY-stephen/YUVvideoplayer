#include "rabbit.cpp"
#include "md5.cpp"
#include <string>
#include <math.h>
int setSbox(unsigned char * Sbox, unsigned char *key,int l){
	int i=0,j=0;
	int IP_Table[63] = {39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,  
        				37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,  
         				35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,  
						33,1,41,9,49,17,57,25,32,0,40,8,48,16,56};
	for(j=0;j<16;j++)
	{
		*(Sbox+j)=*(key+j);//��ʼ����һ��	
		for(i=1;i<7;i++)
			{
			unsigned int n=((*(key+j)-'a')+l+i)%7;
			*(Sbox+j+16*n)=(*(Sbox+j)+*(IP_Table+(j+16*i)%63))%64;//��ʼ����Ӧ��
			}
	}
	return 0;//����
}
/*����˵����messageΪԭ��Ϣָ�룬resultsΪ�����Ϣ��ָ�룬blocksizeΪ����ָ����ÿռ�Ĵ�С������Ϊ16�ı���
keyΪ��Կ��timeΪʹ����Կ�Ĵ�����levelΪ���ܵȼ�*/
int encrypt(unsigned char* message,unsigned char* results,int blocksize,string key,int*t,int level){
	rabbit_instance E1,E2;//rabbit ��ʼ��
	rabbit_instance* p1=&E1;
	rabbit_instance* p2=&E2;
	int times=*t;
	unsigned char Sbox[7][16];//��ʼ��S��
	int n=times/112;//����Կ�ӳٸ���
	int r=times%112;//����S��ģʽ
	int l=key.length();
	size_t h=0;
	int temp=(abs((int)(key[0]+key[l-1]-key[(l-1)/2]))*61)%2609;
	if (blocksize%16) return -1;//��ȷ��һ������Խ��������ٵ���
	unsigned char m_iv[8];//��ʼ����ʼ����
	MD5 md5;
	md5.update(key);	//����MD5��
	unsigned char m_key[16];
	int i=0;
	for(i=0;i<16;i++){
		m_key[i]=(md5.toString()).at(i);//��ֵ��Կ
	}
	if(level==0)
	setSbox(&Sbox[0][0],m_key,0);//����S��
	else
	setSbox(&Sbox[0][0],m_key,temp);
	if(level){//��Կ��չ������Ӱ��
		for(i=0;i<16;i++) m_key[i]=Sbox[r%7][(1+r%16)];
	}
	if(level==2)
	{
		h=n+long(pow(temp%11,r%7))%2609;//ƽ��ֵ
		h=h-h%16+r*16;
	}
	for(i=0;i<8;i++) m_iv[i]=m_key[2*i]+i;//���ó�ʼֵ
	rabbit_key_setup(p1,m_key,16);
	rabbit_iv_setup(p1,p2,m_iv,8);
	rabbit_cipher(p2,message,results,blocksize,h);//ƽ�Ƽ����ļ�
	return 0;//�ɹ�����
}
//��Կ��չS��
