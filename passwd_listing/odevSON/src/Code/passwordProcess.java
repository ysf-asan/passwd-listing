package Code;

import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class passwordProcess {

    public void passwordProcess() throws IOException {
        String[] folders = {"Processed", "Index"};
        for (String folderName : folders) {
            File folder = new File(folderName);
            if (!folder.exists()) {
                folder.mkdir();
                System.out.println("Folder created: " + folderName);
            }
        }
    }

    public void processPasswords() {
        File sourceFolder = new File("src/Unprocessed-Passwords");
        File targetFolder = new File("Processed");
        File[] files = sourceFolder.listFiles();

        List<Thread> threads = new ArrayList<>();

        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().endsWith(".txt")) {
                    Thread thread = new Thread(() -> {
                        processFile(file);
                        moveFile(file, targetFolder);
                        notifyUser("File processing completed for: " + file.getName());
                    });
                    threads.add(thread);
                    thread.start();
                }
            }
        }

        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void processFile(File file) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            Map<String, List<String>> indexMap = new HashMap<>();

            while ((line = br.readLine()) != null) {
                String password = line.trim();
                if (password.isEmpty()) continue;

                String index = String.valueOf(password.charAt(0)).toLowerCase();
                if ("!$#&*-:|<?*".contains(index)) {
                    index = "others";
                }

                indexMap.computeIfAbsent(index, k -> new ArrayList<>()).add(password);
            }

            for (Map.Entry<String, List<String>> entry : indexMap.entrySet()) {
                String folderName = "Index/" + entry.getKey();
                File indexFolder = new File(folderName);

                if (!indexFolder.exists()) {
                    indexFolder.mkdir();
                }

                writePasswordsToFile(entry.getValue(), indexFolder, entry.getKey());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writePasswordsToFile(List<String> passwords, File folder, String index) {
        try {
            List<String> existingPasswords = new ArrayList<>();
            int fileCount = getFileCount(folder, index);
            File indexFile = new File(folder, index + (fileCount > 1 ? fileCount : "") + ".txt");

            if (indexFile.exists()) {
                existingPasswords = Files.readAllLines(indexFile.toPath());
            }

            Set<String> allPasswords = new LinkedHashSet<>(existingPasswords);
            allPasswords.addAll(passwords);

            List<String> passwordList = new ArrayList<>(allPasswords);

            int start = 0;
            while (start < passwordList.size()) {
                List<String> subList = passwordList.subList(start, Math.min(start + 10000, passwordList.size()));
                writeFile(new File(folder, index + (start / 10000 + 1) + ".txt"), subList);
                start += 10000;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeFile(File file, List<String> passwords) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            for (String password : passwords) {
                writer.write(password);
                writer.newLine();
            }
        }
    }

    private int getFileCount(File folder, String index) {
        File[] files = folder.listFiles();
        int count = 1;
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().startsWith(index) && file.getName().endsWith(".txt")) {
                    count++;
                }
            }
        }
        return count;
    }

    public void moveFile(File file, File destinationFolder) {
        File newFile = new File(destinationFolder.getPath() + File.separator + file.getName());
        if (file.renameTo(newFile)) {
            System.out.println("File successfully moved: " + file.getName());
            if (file.exists() && !file.delete()) {
                System.out.println("Failed to delete original file: " + file.getName());
            }
        } else {
            System.out.println("File could not be moved: " + file.getName());
        }
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        byte[] md5Hash = md5.digest(password.getBytes());
        byte[] sha1Hash = sha1.digest(password.getBytes());
        byte[] sha256Hash = sha256.digest(password.getBytes());

        return bytesToHex(md5Hash) + "|" + bytesToHex(sha1Hash) + "|" + bytesToHex(sha256Hash);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public void notifyUser(String message) {
        System.out.println(message);
    }

    public static void savePassword(String password, String indexFolderPath) {
        File indexFile = new File(indexFolderPath + File.separator + "passwords.txt");
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(indexFile, true))) {
            bw.write(password);
            bw.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void searchPassword(String query, File indexFolder) {
        char firstChar = query.charAt(0);
        String indexFolderPath = indexFolder.getPath() + File.separator + Character.toLowerCase(firstChar);
        File folder = new File(indexFolderPath);

        if (!folder.exists() || !folder.isDirectory()) {
            System.out.println("Index folder not found, creating new index folder and file.");
            folder.mkdir();
            savePassword(query, indexFolderPath);
            return;
        }

        File[] indexFiles = folder.listFiles((dir, name) -> name.endsWith(".txt"));
        if (indexFiles != null) {
            for (File indexFile : indexFiles) {
                try (BufferedReader br = new BufferedReader(new FileReader(indexFile))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        String password = line.trim();
                        if (password.equals(query)) {
                            try {
                                String hashedPassword = hashPassword(password);
                                System.out.println("Password found: " + password + "|" + hashedPassword + "|" + indexFile.getName());
                            } catch (NoSuchAlgorithmException e) {
                                e.printStackTrace();
                            }
                            return;
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        System.out.println("Password not found, saving the searched password: " + query);
        savePassword(query, indexFolderPath);
    }

}