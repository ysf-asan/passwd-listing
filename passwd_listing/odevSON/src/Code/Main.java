package Code;

import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        File unprocessedFolder = new File("Unprocessed-Passwords");
        File processedFolder = new File("Processed");
        File indexFolder = new File("Index");

        passwordProcess PP = new passwordProcess();
        PP.passwordProcess();
        PP.processPasswords();
        PP.searchPassword("_a7ccpklm8w_", indexFolder);
        PP.searchPassword("123456789", indexFolder);
        PP.searchPassword("6081jdsh", indexFolder);
        PP.searchPassword("_z_a_q_", indexFolder);
        PP.searchPassword("wollimann55", indexFolder);
        PP.searchPassword("xKkVVCchC1", indexFolder);
        PP.searchPassword("usmc", indexFolder);
        PP.searchPassword("myprofile", indexFolder);
        PP.searchPassword("eltipo", indexFolder);
        PP.searchPassword("=Yh3z#8!C27sbZ4i", indexFolder);






    }
}
