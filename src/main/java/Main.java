import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.errors.EncodingException;

import java.util.Scanner;

public class Main {
    private static boolean validate = false;
    private static boolean canonize = false;
    private static boolean encodeURL = false;
    private static boolean encodeHTML = false;
    private static boolean encodeSQL = false;
    private static boolean validated = false;
    private final static String context = "SIp6";
    private static Encoder encoder = ESAPI.encoder();
    private static Validator validator = ESAPI.validator();


    public static void main (String[] args) {

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-v":
                    validate = true;
                    break;
                case "-c":
                    canonize = true;
                    break;
                case "-e":
                    i ++;
                    switch (args[i])  {
                        case "SQL":
                            encodeSQL = true;
                            break;
                        case "HTML":
                            encodeHTML = true;
                            break;
                        case "URL":
                            encodeURL = true;
                            break;
                    }
                    break;
            }
        }

        Scanner scanner = new Scanner(System.in);
        String entrada = "";
        String[] notEncoded = new String[8];
        String[] encodedURL = new String[8];
        String[] encodedHTML = new String[8];
        String[] encodedSQL = new String[8];

        MySQLCodec codec = new MySQLCodec(MySQLCodec.Mode.STANDARD);

        for (int i = 0; i < 8; i++) {
            entrada = scanner.nextLine();

            if (canonize) {
                entrada = encoder.canonicalize(entrada);
            }

            notEncoded[i] = entrada;

            if (validate) {
                switch (i) {
                    case 0 :
                        validated = validator.isValidInput(context,entrada,"CCName",50,false);
                        break;
                    case 1 :
                        validated = validator.isValidInput(context,entrada,"CCAddress",50,false);
                        break;
                    case 2 :
                        validated = validator.isValidInput(context,entrada,"CCType",4,false);
                        break;
                    case 3 :
                        validated = validator.isValidInput(context,entrada,"CCNumber",16,false);
                        break;
                    case 4 :
                        validated = validator.isValidInput(context,entrada,"CCExpMonth",2,false);
                        break;
                    case 5 :
                        validated = validator.isValidInput(context,entrada,"CCExpYear",4,false);
                        break;
                    case 6 :
                        validated = validator.isValidInput(context,entrada,"CCCVN",3,false);
                        break;
                    default :
                        validated = validator.isValidInput(context,entrada,"CCDNI",9,false);
                        break;
                }
                System.out.println(validated);
                if(!validated) {
                    break;
                }
            }

            if (encodeSQL) {
                encodedSQL[i] = encoder.encodeForSQL(codec,entrada);
            }
            if (encodeURL) {
                try {
                    encodedURL[i] = encoder.encodeForURL(entrada);
                } catch (EncodingException e) {
                    e.printStackTrace();
                }
            }
            if (encodeHTML) {
                encodedHTML[i] = encoder.encodeForHTML(entrada);
            }


        }
        if(!validated) {
            System.out.println("Your entry is not valid!");
        }
        else if(!(encodeHTML || encodeSQL || encodeURL)) {
            printArray("plain",notEncoded);
        } else {
            if(encodeHTML) {
                printArray("HTML",encodedHTML);
            }
            if(encodeSQL) {
                printArray("SQL",encodedSQL);
            }
            if(encodeURL) {
                printArray("URL",encodedURL);
            }
        }

    }

    /**
     * Aux method to print an out array
     */
    private static void printArray(String type, String[] array) {
        if (!type.contains("plain")) {
            System.out.println("\nYour entry encoded in " + type + ":");
        } else {
            System.out.println("\nYour entry:");
        }
        for (int i = 0; i < array.length; i++) {
            System.out.println("   "+array[i]);
        }
        System.out.println("");
    }
}
