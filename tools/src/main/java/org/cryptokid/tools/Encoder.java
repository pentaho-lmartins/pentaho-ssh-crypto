package org.cryptokid.tools;

import org.cryptokid.core.encryption.SSHTwoWayPassworkEncoder;
import org.pentaho.di.core.KettleClientEnvironment;
import org.pentaho.di.core.encryption.TwoWayPasswordEncoderInterface;
import org.pentaho.di.core.exception.KettleException;

public class Encoder {

  private static TwoWayPasswordEncoderInterface encoder = new SSHTwoWayPassworkEncoder();

  public static void main( String[] args ) {
    System.out.println( "CryptoKid Encoder" );

    try {
      KettleClientEnvironment.init();
      encoder.init();

      System.out.println( encoder.encode( args[0], true ) );
    } catch ( KettleException e ) {
      System.err.println( e.getMessage() );
    }
  }
}
