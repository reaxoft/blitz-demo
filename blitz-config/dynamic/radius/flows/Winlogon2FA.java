package com.identityblitz.idp.radius.flow;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.util.Arrays;
import com.identityblitz.idp.radius.flow.RadiusResult.*;

public class Winlogon2FA implements RadiusFlow {

  private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.radius");

  public String loginN12(final String login) {
    return login;
  }

  public RadiusResult next(final RadiusContext context) {
    if (context.factor() == 1) {
      return RadiusResult.challenge(Challenges.password());
    } else if (context.factor() == 2) {
      final java.util.Map<String, String> answers = new java.util.HashMap<String, String>();
      
      String[] allowed2FAMethods = {"sms", "totp", "trustKey", "flex_aladdin_otp", "flex_aladdin_push", "flex_aladdin_sms"};            
      
      int counter = 1;
      for ( String allowedValue : allowed2FAMethods ) {
        if ( context.availableMethods().contains(allowedValue) ) {
            String key = "#" + allowedValue;
            if (allowedValue.equals("sms") || allowedValue.equals("flex_aladdin_sms")) {
                key = key + "$11";
            } else if (allowedValue.equals("totp") || allowedValue.equals("flex_aladdin_otp")) {
                key = key + "$10";
            } else if (allowedValue.equals("trustKey") || allowedValue.equals("flex_aladdin_push")) {
                key = key + "$01";
            }
            answers.put(key, allowedValue);
            counter++;
        }
      }

      return RadiusResult.dialog("winlogon", answers, "${key}");
    }
    return  RadiusResult.authenticated(context.subject());
  }


  public RadiusResult dialog(final RadiusContext context,
                             final String message,
                             final java.util.Map<String, String> answers,
                             final String answer) {
    if(message.equals("winlogon")) {
      final String challenge = answers.get(answer);
        if(challenge != null) return RadiusResult.challenge(Challenges.byDialogName(challenge));
        else return RadiusResult.dialog(message, answers);
    } else {
      return RadiusResult.rejected("unsupportedMessage");
    }
  }

}