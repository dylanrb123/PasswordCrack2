/**
 * PasswordCrack2.java
 */

import edu.rit.pj2.ObjectLoop;
import edu.rit.pj2.Task;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;

/**
 * Main class that carries out parallel brute-force attack on a password hash database
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 */
public class PasswordCrack2 extends Task {

    /** Map of the usernames and hashes from the file, key = hash, value = username */
    HashMap<String, String> userDict = new HashMap<String, String>();

    /** Map of generates passwords and hashes. key = hash, value = original password  */
    ConcurrentHashMap<String, String> hashes = new ConcurrentHashMap<String, String>();

    /** Number of matches found */
    int numMatches = 0;

    @Override
    public void main(String[] args) throws Exception {
        // verify command line args
        if(args.length != 1) {
            System.err.println("Usage: java PasswordCrack2 <databaseFile>");
            System.exit(1);
        }

        String fileName = args[0];
        BufferedReader fileReader = new BufferedReader(new FileReader(fileName));
        try {
            String line = fileReader.readLine();
            while(line != null) {
                String[] temp = line.split("\\s+");
                userDict.put(temp[1], temp[0]);
                line = fileReader.readLine();
            }
        } finally {
            fileReader.close();
        }

        Set<String> passwords = generatePasswords();
        generateHashes(passwords);
        matchHashes();
    }

    /**
     * Generates a set of all possible passwords given a character set of a-z, 0-9
     * @return the set of passwords
     */
    public Set<String> generatePasswords() {
        Set<String> passwords = new HashSet<String>();
        Set<Character> characters = new HashSet<Character>();
        for(char c = 'a'; c <= 'z'; c++) {
            characters.add(c);
        }
        for(char c = '0'; c <= '9'; c++) {
            characters.add(c);
        }
        // add one char passwords
        for(char c : characters) {
            passwords.add(Character.toString(c));
        }
        // add two char passwords
        for(char c : characters) {
            for (char d : characters) {
                StringBuilder pass = new StringBuilder();
                pass.append(c).append(d);
                passwords.add(pass.toString());
            }
        }
        // add three char passwords
        for(char c : characters) {
            for(char d : characters) {
                for(char e : characters) {
                    StringBuilder pass = new StringBuilder();
                    pass.append(c).append(d).append(e);
                    passwords.add(pass.toString());
                }
            }
        }
        // add four char passwords
        for(char c : characters) {
            for(char d : characters) {
                for(char e : characters) {
                    for(char f : characters) {
                        StringBuilder pass = new StringBuilder();
                        pass.append(c).append(d).append(e).append(f);
                        passwords.add(pass.toString());
                    }
                }
            }
        }

        return passwords;
    }

    /**
     * Generates hashes of all of the passwords
     * @param passwords set of passwords to hash
     */
    private void generateHashes(Set<String> passwords) {
        parallelFor(passwords).exec(new ObjectLoop<String>() {
            @Override
            public void run(String s) throws Exception {
                MessageDigest md = null;
                try {
                    md = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    System.exit(1);
                }
                byte[] data = null;
                try {
                    data = s.getBytes("UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                    System.exit(1);
                }
                md.update(data);
                data = md.digest();

                StringBuilder hexVal = new StringBuilder();
                for(int i = 0; i < data.length; i++) {
                    String hs = Integer.toHexString(0xFF & data[i]);
                    if(hs.length() == 1) hexVal.append('0');
                    hexVal.append(hs);
                }
                hashes.put(hexVal.toString(), s);
                
            }
        });

    }

    /**
     * finds matches for password hashes in parallel
     */
    private void matchHashes() {
        parallelFor(hashes.keySet()).exec(new ObjectLoop<String>() {
            @Override
            public void run(String s) throws Exception {
                
                // found a match
                if(userDict.containsKey(s)) {
                    System.out.println(userDict.get(s) + " " + hashes.get(s));
		            numMatches++;
                }
            }
        });

	System.out.println(userDict.size() + " users");
	System.out.println(numMatches + " passwords found");
    }
}
