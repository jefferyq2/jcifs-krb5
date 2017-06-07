package jcifs.smb;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import jcifs.util.LogStream;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

// >>SmbAuthenticator
/**
 * This class used to provide Kerberos feature when setup GSSContext.
 * 
 * @author Shun
 */
class Kerb5Context {
    private static final LogStream log = LogStream.getInstance();
    private static final String OID = "1.2.840.113554.1.2.2";
    
    private static boolean deprecationWarningPrinted = false;
    
    private final GSSContext gssContext;
    
    Kerb5Context(
            String host, 
            String service, 
            String name,
            int userLifetime,
            int contextLifetime
            ) throws GSSException{
        GSSManager manager = GSSManager.getInstance();
        Oid oid = null; 
        GSSName serviceName = null;
        GSSName clientName = null;
        GSSCredential clientCreds = null;
        
        oid = new Oid(OID);

        serviceName = manager.createName(
                service + "@" + host, GSSName.NT_HOSTBASED_SERVICE, oid);
        if(name!=null){
            clientName = manager.createName(name, GSSName.NT_USER_NAME, oid);
            clientCreds = manager.createCredential(
                        clientName, userLifetime, oid, GSSCredential.INITIATE_ONLY);
        }
        gssContext = manager.createContext(
                serviceName,
                oid,
                clientCreds,
                contextLifetime);
    }
    
    GSSContext getGSSContext(){
        return gssContext;
    }
    
    /**
     * Extract the context session key from the gssContext. The subject is only
     * used if no support for extraction of the session key is not possible
     * with an API and is used as a fallback method.
     * 
     * @param subject
     * @return context session key
     * @throws GSSException 
     */
    Key searchSessionKey(Subject subject) throws GSSException{
        /*
        The kerberos session key is not accessible via the JGSS API IBM and 
        Oracle both implement a similar API to make an ExtendedGSSContext
        available.
        
        The older implementation to find the session key is still available as 
        a fallback, but it is not expected, that it works.
        
        From "JCIFS with Kerberos doesn't work on JDK 7":
        
        https://bugs.openjdk.java.net/browse/JDK-8031973:
        
        This is a bug in JCIFS. It seems the SMB packet it generates that 
        includes the AP-REQ token also includes something else that should be 
        encrypted with the *context* session key. The standard GSS-API does not
        provide such a method so it looks up the service ticket in the subject 
        and use its *ticket* session key instead. The context session key is not 
        the ticket session key if sub key is used.
         
        Possible patch: Fix jcifs.smb.Kerb5Context's searchSessionKey() method 
        to call Oracle JDK's 
        ExtendedGSSContext::inquireSecContext(InquireType.KRB5_GET_SESSION_KEY) 
        to get the real session key. The classes are defined in 
        com.sun.security.jgss. 
        */
        
        if (extendedGSSContextClass == null || inquireTypeSessionKey == null
                || inquireSecContext == null || gssContext == null) {
            
            if(log.level > 0 && (! deprecationWarningPrinted)) {
                log.print("WARNING: Kerberos Session Key is extracted from Kerberos Ticket. This is known to be problematic (See: https://bugs.openjdk.java.net/browse/JDK-8031973).");
                deprecationWarningPrinted = true;
            }
            
            MIEName src = new MIEName(gssContext.getSrcName().export());
            MIEName targ = new MIEName(gssContext.getTargName().export());
            for(KerberosTicket ticket: subject.getPrivateCredentials(KerberosTicket.class)) {
                MIEName client = new MIEName(gssContext.getMech(), ticket.getClient().getName());
                MIEName server = new MIEName(gssContext.getMech(), ticket.getServer().getName());
                if (src.equals(client) && targ.equals(server)) {
                    return ticket.getSessionKey();
                }
            }
            return null;
        } else {
            if (extendedGSSContextClass.isAssignableFrom(gssContext.getClass())) {
                try {
                    return (Key) inquireSecContext.invoke(gssContext, new Object[]{inquireTypeSessionKey});
                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
                    log.print("Reflective access to ExtendedGSSContext failed");
                    ex.printStackTrace(log);
                }
            }
            return null;
        }
    }
    
    public void dispose() throws GSSException {
        if(gssContext != null){
            gssContext.dispose();
        }
    }
    
    /*
     * Prepare reflective access to ExtendedGSSContext. The reflective access
     * abstracts the acces so far, that Oracle JDK, Open JDK and IBM JDK are
     * supported.
     * 
     * At the time of the first implementation only a test on Oracle JDK was
     * done.
     */

    private static final String OPENJDK_JGSS_INQUIRE_TYPE_CLASS = "com.sun.security.jgss.InquireType";
    private static final String OPENJDK_JGSS_EXT_GSSCTX_CLASS = "com.sun.security.jgss.ExtendedGSSContext";
    
    private static final String IBM_JGSS_INQUIRE_TYPE_CLASS = "com.ibm.security.jgss.InquireType";
    private static final String IBM_JGSS_EXT_GSSCTX_CLASS = "com.ibm.security.jgss.ExtendedGSSContext";
    
    private final static Class extendedGSSContextClass;
    private final static Method inquireSecContext;
    private final static Object inquireTypeSessionKey;
    
    static {
        Class extendedGSSContextClassPrep = null;
        Method inquireSecContextPrep = null;
        Object inquireTypeSessionKeyPrep = null;
        
        if (extendedGSSContextClassPrep == null || inquireSecContextPrep == null || inquireTypeSessionKeyPrep == null) {
            try {
                extendedGSSContextClassPrep = Class.forName(OPENJDK_JGSS_EXT_GSSCTX_CLASS);
                Class inquireTypeClass = Class.forName(OPENJDK_JGSS_INQUIRE_TYPE_CLASS);
                inquireSecContextPrep = extendedGSSContextClassPrep.getMethod("inquireSecContext", inquireTypeClass);
                inquireTypeSessionKeyPrep = Enum.valueOf(inquireTypeClass, "KRB5_GET_SESSION_KEY");
            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException ex) {
                if (log.level > 3) {
                    log.println("Failed to initalize ExtendedGSSContext initializdation for OracleJDK / OpenJDK");
                    ex.printStackTrace(log);
                }
            }
        }
        if (extendedGSSContextClassPrep == null || inquireSecContextPrep == null || inquireTypeSessionKeyPrep == null) {
            try {
                extendedGSSContextClassPrep = Class.forName(IBM_JGSS_EXT_GSSCTX_CLASS);
                Class inquireTypeClass = Class.forName(IBM_JGSS_INQUIRE_TYPE_CLASS);
                inquireSecContextPrep = extendedGSSContextClassPrep.getMethod("inquireSecContext", inquireTypeClass);
                inquireTypeSessionKeyPrep = Enum.valueOf(inquireTypeClass, "KRB5_GET_SESSION_KEY");
            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException ex) {
                if (log.level > 3) {
                    log.println("Failed to initalize ExtendedGSSContext initializdation for IBM JDK");
                    ex.printStackTrace(log);
                }
            }
        }
        extendedGSSContextClass = extendedGSSContextClassPrep;
        inquireSecContext = inquireSecContextPrep;
        inquireTypeSessionKey = inquireTypeSessionKeyPrep;
        
        if (extendedGSSContextClass != null && inquireSecContext != null && inquireTypeSessionKey != null) {
            if (log.level > 3) {
                log.println("Found ExtendedGSSContext implementation: " + extendedGSSContextClass.getName());
            }
        }
    }
}
// SmbAuthenticator<<
