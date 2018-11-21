package org.cryptokid.core.encryption;

import com.jcraft.jsch.agentproxy.AgentProxy;
import com.jcraft.jsch.agentproxy.AgentProxyException;
import com.jcraft.jsch.agentproxy.connector.SSHAgentConnector;
import com.jcraft.jsch.agentproxy.usocket.JNAUSocketFactory;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.pentaho.di.core.encryption.TwoWayPasswordEncoderInterface;
import org.pentaho.di.core.encryption.TwoWayPasswordEncoderPlugin;
import org.pentaho.di.core.exception.KettleException;
import org.pentaho.di.core.util.EnvUtil;
import org.pentaho.di.core.util.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@TwoWayPasswordEncoderPlugin( id = "SSH", name = "SSH Password Encoder",
  description = "Encrypts and decrypts passwords using a key generated from an SSH private key." )
public class SSHTwoWayPassworkEncoder implements TwoWayPasswordEncoderInterface {

  private static final String PREFIX = "SSH ";
  private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KETTLE_SSH_PRIVATE_KEY_FILE = "KETTLE_SSH_PRIVATE_KEY_FILE";
  private static final String KETTLE_SSH_ENCRYPTION_STRENGTH = "KETTLE_SSH_CRYPTO_STRENGTH";
  private static final String DEFAULT_ENCRYPTION_STRENGTH = "128"; // 128 bits

  private static final int IV_LENGTH = 16; // IV is always 16 bytes long

  private IvParameterSpec iv;
  private SecretKeySpec key;

  @Override
  public void init() throws KettleException {
    try {
      AgentProxy agent = new AgentProxy( new SSHAgentConnector( new JNAUSocketFactory() ) );

      if ( !agent.isRunning() ) {
        throw new KettleException( "SSH agent not running." );
      }

      byte[] blob = Arrays.stream( agent.getIdentities() )
        .filter( identity -> new String( identity.getComment() ).equals( EnvUtil.getSystemProperty( KETTLE_SSH_PRIVATE_KEY_FILE ) ) )
        .findFirst()
        .orElseThrow( () -> new KettleException( "SSH key not found in SSH agent." ) ).getBlob();

      byte[] signature = agent.sign( blob, ALGORITHM.getBytes( Charsets.UTF_8 ) );
      String strength = EnvUtil.getSystemProperty( KETTLE_SSH_ENCRYPTION_STRENGTH, DEFAULT_ENCRYPTION_STRENGTH );

      iv = new IvParameterSpec( Arrays.copyOf( signature, IV_LENGTH ) );
      key = new SecretKeySpec( Arrays.copyOfRange( signature, IV_LENGTH, IV_LENGTH + Integer.parseInt( strength ) / 8 ), "Rijndael" );
    } catch ( AgentProxyException e ) {
      throw new KettleException( e );
    }
  }

  @Override
  public String encode( String password ) {
    return encode( password, false );
  }

  @Override
  public String encode( String password, boolean prefix ) {
    if ( StringUtil.isEmpty( password ) ) {
      return password;
    }

    List<String> variables = new ArrayList<>();
    StringUtil.getUsedVariables( password, variables, true );

    if ( !variables.isEmpty() ) {
      // don't encrypt a variable name!
      return password;
    }

    try {
      Cipher cipher = Cipher.getInstance( ALGORITHM );
      cipher.init( Cipher.ENCRYPT_MODE, key, iv );

      String encrypted = Base64.encodeBase64String( cipher.doFinal( password.getBytes( Charsets.UTF_8 ) ) );
      return prefix ? PREFIX + encrypted : encrypted;
    } catch ( GeneralSecurityException e ) {
      throw new RuntimeException( "Unable to encrypt password.", e );
    }
  }

  @Override
  public String decode( String encoded, boolean option ) {
    if ( StringUtil.isEmpty( encoded ) ) {
      return encoded;
    }

    try {
      Cipher cipher = Cipher.getInstance( ALGORITHM );
      cipher.init( Cipher.DECRYPT_MODE, key, iv );

      String encrypted = option && encoded.startsWith( PREFIX ) ? encoded.substring( PREFIX.length() ) : encoded;
      return new String( cipher.doFinal( Base64.decodeBase64( encrypted ) ) );
    } catch ( GeneralSecurityException e ) {
      throw new RuntimeException( "Unable to encrypt password.", e );
    }
  }

  @Override
  public String decode( String encoded ) {
    return decode( encoded, false );
  }

  @Override
  public String[] getPrefixes() {
    return new String[] { PREFIX };
  }
}
