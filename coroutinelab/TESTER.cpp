#include<cstdlib>
#include<cstdio>

using namespace std;

int main()
{
    int l[3]={16,24,32};
    int m[3]={10000,100000,1000000};
    int b[6]={1,2,4,8,16,32};
    for(int i=0;i<3;i++)
    {
        for(int j=0;j<3;j++)
        {
            for(int k=0;k<6;k++)
            {
                char cmd[100];
                sprintf(cmd,"./binary_search -l %d -m %d -b %d >./logs/bs_l%d_m%d_b%d",l[i],m[j],b[k],l[i],m[j],b[k]);
                system(cmd);
            }
        }
    }
}