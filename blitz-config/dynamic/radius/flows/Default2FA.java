package com.identityblitz.idp.radius.flow;

import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.Arrays;

import org.slf4j.Logger;
import com.identityblitz.idp.radius.flow.RadiusResult.*;

public class Default2FA implements RadiusFlow {

  private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.radius");

  public String loginN12(final String login) {
    return login;
  }

  public RadiusResult next (final RadiusContext context) {
    if (context.factor() == 1) {
      return RadiusResult.challenge(Challenges.password());
    } else if (context.factor() == 2) {
      final java.util.Map<String, String> answers = new java.util.TreeMap<String, String>();

      logger.debug("### Run 2 FA: subId={}, methods={}", context.subject(), context.availableMethods());

      String[] allowed2FAMethods = {"sms", "totp", "trustKey", "flex_aladdin_otp", "flex_aladdin_push", "flex_aladdin_sms"};
      logger.debug("### allowed2FAMethods={}", Arrays.toString(allowed2FAMethods));

      int counter = 1;
      for ( String allowedValue : allowed2FAMethods ) {
        if ( context.availableMethods().contains(allowedValue) ) {
            answers.put(String.valueOf(counter), allowedValue);
            counter++;
        }
      }

      logger.debug("### next answers={}", answers);

      return RadiusResult.dialog("challengeChoose", answers,"${key} - ${desc}");
    } else {
      return  RadiusResult.authenticated(context.subject());
    }
  }

  public RadiusResult dialog(final RadiusContext context,
                             final String message,
                             final java.util.Map<String, String> answers,
                             final String answer) {

    if (message.equals("challengeChoose")) {
      final String challenge = answers.get(answer);
      logger.debug("### challenge={}", challenge);
      logger.debug("### message={}", message);
      logger.debug("### dialog answers={}", answers);

      if(challenge != null) {
        return RadiusResult.challenge(Challenges.byDialogName(challenge));
      } else {
        return RadiusResult.dialog(message, answers);
      }
    } else {
        return RadiusResult.rejected("unsupportedMessage");
    }
  }

}