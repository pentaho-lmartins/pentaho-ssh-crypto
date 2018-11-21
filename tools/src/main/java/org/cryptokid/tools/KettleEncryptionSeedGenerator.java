package org.cryptokid.tools;

import java.util.Random;

public class KettleEncryptionSeedGenerator {

  private static final int SEED_LENGTH = 40;

  public static void main( String[] args ) {
    System.out.println( "CryptoKid Kettle Seed Generator" );

    StringBuilder builder = new StringBuilder();
    Random random = new Random();

    for ( int i = 0; i < SEED_LENGTH; i++ ) {
      // generate a random char between ASCII code 48 and 57 (0 to 9)
      int c = random.nextInt( 10 ) + 48;
      builder.append( (char) c );
    }

    System.out.printf( "KETTLE_TWO_WAY_PASSWORD_ENCODER_SEED=%s%n", builder.toString() );
  }
}
