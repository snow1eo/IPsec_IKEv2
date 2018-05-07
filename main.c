/* test IKE */

#include "ike.h"

int main (void)
{
    for (int i = 0; i < 10000; i++)
    {
        init ();
        ike_init ();
        // puts ("====================== FIRST PACKET =====================");
        // print_packet ();
        // puts ("=========================================================");

        receive ();
        // puts ("===================== SECOND PACKET =====================");
        // print_packet ();
        // puts ("=========================================================");

        ike_auth ();
        // puts ("====================== THIRD PACKET =====================");
        // print_packet ();
        // puts ("=========================================================");

        receive ();
        // puts ("===================== FOURTH PACKET =====================");
        // print_packet ();
        // puts ("=========================================================");
        // reset ();
        mem_clr ();

        printf ("PASS: %d\n", i);
    }
    // puts ("\nDONE");
    // system ("sleep 10");
    return 0;
}