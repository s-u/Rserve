
import org.rosuda.REngine.REXP;
import org.rosuda.REngine.REXPMismatchException;
import org.rosuda.REngine.Rserve.RConnection;
import org.rosuda.REngine.Rserve.RserveException;

/**
 *
 * @author richet
 */
public class RserveBug {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws RserveException, REXPMismatchException {
        
        RConnection c = new RConnection();
        try {
            REXP array43 = c.eval("array(0,c(4,3))");
            double[][] m43 = array43.asDoubleMatrix();
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("ERROR: " + e);
            try {
              c.serverShutdown();
            } catch (RserveException ee) {
              System.err.println("WARNING: " + ee);
            }
            System.exit(1);
        }
        System.err.println("SUCCESS.");
        try {
           c.serverShutdown();
        } catch (RserveException ee) {
          System.err.println("WARNING: " + ee);
        }
        System.exit(0);
    }

}
