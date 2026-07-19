/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package denemelerim;

public class LBlock {
    private static final byte [][] S = {{
        14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5
    },{
        4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3
    },{
        1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10
    },{
        7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1
    },{
        14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3
    },{
        2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5
    },{
        11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2
    },{
        13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6
    }};
    public static void fiestelNetwork(int[] x, int[] randomKey) {

        int xL[] = new int[32];
        int xR[] = new int[32];

        for (int i = 0; i < 64; i++) {
            if (i < 32) {
                xL[i] = x[i];
            } else {
                xR[i - 32] = x[i];
            }
        }  
        int sayac=0;
        for (int i = 0; i < 64; i++) {
            if (i < 32) {    
                  System.out.print(""+xL[i]);
            } else {
                  System.out.print(""+xR[i-32]);
            }
        }
        
        int[] solBitler = new int[32];
        int[] sagBitler = new int[32];
        int[] travelTemp = new int[32];

        sagBitler = LBlock.leftShift(xR, 8, true);
                
        System.out.print("\nxR[0]=");
        for (int j = 0; j < 32; j++) {
            System.out.print(xR[j]);
        }         
        
       System.out.println("\n++++++ENCRYPTION++++++");
       for (int i = 0; i < 32; i++) {
            System.out.print("\n\n************\nRound "+i+":\nRound Key =  ");
            randomKeyYaz(randomKey);
            travelTemp = xL;
            xL=solBitler;
            xR=sagBitler;
            System.out.print("\n\n\nL["+i+"]=");
                     
            for (int j = 0; j < 32; j++) {
                System.out.print(xL[i]);
            }
            System.out.print("\nR["+i+"]=");
            for (int j = 0; j < 32; j++) {
                System.out.print(xR[i]);
            }
            randomKey = RandomDegerGetirici.nAdetRandomBitGetir(32);
        }
    }
public static void randomKeyYaz(int[] printThis){
    for (int j = 0; j < 32; j++) {
        System.out.print(printThis[j]);
    }
}
    public static int[] leftShift(int[] bits, int n, boolean isLeft) {
        int answer[] = new int[bits.length];

        System.arraycopy(bits, 0, answer, 0, bits.length);

        for (int i = 0; i < n; i++) {
            int temp = answer[0];
            for (int j = 0; j < bits.length - 1; j++) {
                answer[j] = answer[j + 1];
            }
            answer[bits.length - 1] = temp;
        }
        return answer;
    }

    public static int[] roundFunctionF(int[] xL, int[] randomKey) {

        int[] yBitleri = new int[32];
        int[] uBitleri = new int[32];
        
        yBitleri = LBlock.xor(xL, randomKey);
      
        yBitleri = confisionFuctionS(yBitleri);
        return yBitleri;
    }

    public static int[] diffisionFuctionP(int[] zBitleri) {
        int []yeni = new int[zBitleri.length];
        String []s = new String[32];
        for (int i = 0; i < 32; i++) {
            s[i]=""+yeni[i];
        }
        
        String[] dizi = new String[8];    
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                dizi[i] =s [(4*i)+j]+"";
            }
        }
 
        int uBitleri[]=new int[8];       
        uBitleri[0] = Integer.parseInt(dizi[1],2);
        uBitleri[1] = Integer.parseInt(dizi[3],2);
        uBitleri[2] = Integer.parseInt(dizi[0],2);
        uBitleri[3] = Integer.parseInt(dizi[2],2);
        uBitleri[4] = Integer.parseInt(dizi[5],2);
        uBitleri[5] = Integer.parseInt(dizi[7],2);
        uBitleri[6] = Integer.parseInt(dizi[4],2);
        uBitleri[7] = Integer.parseInt(dizi[6],2);   
        return uBitleri;
    }

    public static int[] confisionFuctionS(int[] bits) {
        String []s = new String[32];        
        int uBitleri[]=new int[8];  
        for (int i = 0; i < 8; i++) {  
          uBitleri[i] = bits[i];
        }
        return uBitleri;
    }
    
    private static int[] xor(int[] a, int[] b) {
        int answer[] = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            answer[i] = a[i] ^ b[i];
        }
        return answer;
    }
     public String DecToBin(int n){
        String x = "";
        while(n > 0)
        {   int a = n % 2;
            x = a + x;
            n = n / 2;
        }
        return x;
    }
}
