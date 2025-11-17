package com.identityblitz.idp.flow.dynamic;

import java.lang.*;
import java.util.*;
import java.text.*;
import java.time.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import com.identityblitz.idp.login.authn.flow.Context;
import com.identityblitz.idp.login.authn.flow.Strategy;
import com.identityblitz.idp.login.authn.flow.StrategyState;
import com.identityblitz.idp.login.authn.flow.StrategyBeginState;
import com.identityblitz.idp.login.authn.flow.LCookie;
import com.identityblitz.idp.login.authn.flow.api.*;
import com.identityblitz.idp.flow.common.api.*;
import com.identityblitz.idp.flow.dynamic.*;
import java.lang.invoke.LambdaMetafactory;
import java.util.function.Consumer;
import com.identityblitz.idp.login.authn.flow.StrategyState.*;


public class PipeSecQuestion implements Strategy {

    private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.dynamic");
  	private final static String DOMAIN = "example.com";
    private final static Boolean CAN_SKIP = true;
	
    @Override public StrategyBeginState begin(final Context ctx) {
        if ("login".equals(ctx.prompt())){
            List<String> methods = new ArrayList<String>(Arrays.asList(ctx.availableMethods()));
            methods.remove("cls");
            return StrategyState.MORE(methods.toArray(new String[0]), true);
        } else {
            if(ctx.claims("subjectId") != null)
                return StrategyState.ENOUGH();
            else
                return StrategyState.MORE(new String[]{});
        }
    }
  
    @Override public StrategyState next(final Context ctx) {
        Integer reqFactor = (ctx.user() == null) ? null : ctx.user().requiredFactor();
        if (reqFactor == null || reqFactor.equals(ctx.justCompletedFactor())){
          	if(requireAddSecQsn(ctx)) return addSecQsn(ctx);
            else return StrategyState.ENOUGH();
        } 
        else  return StrategyState.MORE(new String[]{});
    }
  
    private Boolean requireAddSecQsn(final Context ctx) {
        String secQsn = (ctx.user() == null) ? null : ctx.user().securityQuestion();
        Long agreedOn = (ctx.user() == null) ? null : ctx.user().userProps().numProp("pipes.addSecQsn.agreedOn"); 
        Long disagreedOn = (ctx.user() == null) ? null : ctx.user().userProps().numProp("pipes.addSecQsn.disagreedOn"); 
        if (secQsn != null) return false;
        else if (disagreedOn == null) return true;
        else {  
            long now = Instant.now().getEpochSecond();
            return ((now - disagreedOn) > 1);
        }
    }
  
    private StrategyState addSecQsn(final Context ctx) {
        String uri = "https://"+DOMAIN+"/blitz/pipes/secQsn/start?canSkip="+CAN_SKIP+"&appId=_blitz_profile";
        Set<String> claims = new HashSet<String>(){{
          add("instanceId");  
        }};
        Set<String> scopes = new HashSet<String>(){{
            add("openid");        
        }};
       return StrategyState.ENOUGH_BUILDER()
         .withPipe(uri, "_blitz_profile", scopes, claims)
         .build();      
    }
}
