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
import com.identityblitz.idp.login.authn.flow.api.*;
import com.identityblitz.idp.login.authn.flow.Context;
import com.identityblitz.idp.login.authn.flow.Strategy;
import com.identityblitz.idp.login.authn.flow.StrategyState;
import com.identityblitz.idp.login.authn.flow.StrategyBeginState;
import com.identityblitz.idp.login.authn.flow.Enough;
import com.identityblitz.idp.login.authn.flow.More;
import com.identityblitz.idp.login.authn.flow.LCookie;
import com.identityblitz.idp.login.authn.flow.LUserAgent;
import com.identityblitz.idp.login.authn.flow.LBrowser;
import com.identityblitz.idp.flow.common.api.*;
import com.identityblitz.idp.flow.dynamic.*;
import java.lang.invoke.LambdaMetafactory;
import java.util.function.Consumer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static com.identityblitz.idp.login.authn.flow.StrategyState.*;

public class PipeAttrActAdd implements Strategy {

    private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.dynamic");
  	private final static String DOMAIN = "example.com";
  	private final static String MOBILE_ATTR = "phone_number";
  	//private final static String MOBILE_ATTR = null;
    private final static String EMAIL_ATTR = "email";
  	private final static String COMMON_ATTR = "middle_name";
	  private final static Integer SKIP_TIME_IN_SEC = 120;
  	private final static Integer ACT_TIME_IN_SEC = 1*1*1*1;
    private final static Boolean ASK_AT_1ST_LOGIN = false;

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
        Instant instant = Instant.now();
        Boolean new_device = false;
        if (ctx.ua().getNewlyCreated() && ctx.justCompletedFactor() == 1 && !ASK_AT_1ST_LOGIN){
         	logger.debug("User with sub={} is signing in, pid={}, on a new device", ctx.claims("subjectId"), ctx.id());
          	new_device = true;
        }
        Integer reqFactor = ctx.user().requiredFactor();
        if(reqFactor == null || reqFactor == ctx.justCompletedFactor()) {
              Enough.Builder en_builder = StrategyState.ENOUGH_BUILDER();
				if (MOBILE_ATTR !=null && !new_device && requireActualizeAttr(MOBILE_ATTR, ctx)) {
                  	  String uri = "https://"+DOMAIN+"/blitz/pipes/attr/act?attr="+MOBILE_ATTR+"&canSkip=true&appId=_blitz_profile&verified=true";
						Set<String> clms = new HashSet<String>(){{
						  add("instanceId");
						  add(MOBILE_ATTR);
						}};
						Set<String> scps = new HashSet<String>(){{
							add("openid");
						}};
						logger.debug("User has no {} or a non-actualzed {}, so opening pipe", MOBILE_ATTR, MOBILE_ATTR);
						en_builder = en_builder.withPipe(uri, "_blitz_profile", scps, clms);
				} else if (EMAIL_ATTR !=null && !new_device && requireActualizeAttr(EMAIL_ATTR, ctx)) {
                  	  String uri = "https://"+DOMAIN+"/blitz/pipes/attr/act?attr="+EMAIL_ATTR+"&canSkip=true&appId=_blitz_profile&verified=true";
						Set<String> clms = new HashSet<String>(){{
						  add("instanceId");
						  add(EMAIL_ATTR);
						}};
						Set<String> scps = new HashSet<String>(){{
							add("openid");
						}};
						logger.debug("User has no {} or a non-actualzed {}, so opening pipe", EMAIL_ATTR, EMAIL_ATTR);
						en_builder = en_builder.withPipe(uri, "_blitz_profile", scps, clms);
                } else if (COMMON_ATTR !=null && !new_device && requireActualizeAttr(COMMON_ATTR, ctx)) {
                  	  String uri = "https://"+DOMAIN+"/blitz/pipes/attr/act?attr="+COMMON_ATTR+"&canSkip=true&appId=_blitz_profile";
						Set<String> clms = new HashSet<String>(){{
						  add("instanceId");
						  add(COMMON_ATTR);
						}};
						Set<String> scps = new HashSet<String>(){{
							add("openid");
						}};
						logger.debug("User has no {}, so opening pipe", COMMON_ATTR);
						en_builder = en_builder.withPipe(uri, "_blitz_profile", scps, clms);
				}
			return en_builder.build();
        } else {
            return StrategyState.MORE(new String[]{});
        }
    }

    private Boolean requireActualizeAttr(final String attrName, final Context ctx) {
        if (attrName.equals(MOBILE_ATTR) && (ctx.passedTrack().startsWith("1:sms") || ctx.passedTrack().endsWith("sms"))) {
		  logger.debug("User subjectId = {}, pid = {} used SMS, so no actualization needed", ctx.claims("subjectId"), ctx.id());
          return false;
        }
		if (attrName.equals(EMAIL_ATTR) && ctx.passedTrack().endsWith("email")) {
		  logger.debug("User subjectId = {}, pid = {} used EMAIL while auth, so no actualization needed", ctx.claims("subjectId"), ctx.id());
          return false;
        }
        Long skpTime = null;
        Long actTime = null;
        long now = Instant.now().getEpochSecond();
        if (ctx.user().userProps().numProp("pipes.act."+attrName+".skippedOn") != null) {
          	skpTime = ctx.user().userProps().numProp("pipes.act."+attrName+".skippedOn");
        }
      	if (skpTime != null && ((now - skpTime) < SKIP_TIME_IN_SEC)) {
          logger.debug("User subjectId = {}, pid = {} has skipped update '{}' only '{}' seconds ago, no actualization needed", ctx.claims("subjectId"), ctx.id(), attrName, (now - skpTime));
          return false;
        }
        if (ctx.claims(attrName) == null) return true;
        else {
          if (ctx.user().attrsCfmTimes() != null) {
          	actTime = ctx.user().attrsCfmTimes().get(attrName);
          }
          if (actTime == null) return true;
          else {
            logger.debug("User subjectId = {}, pid = {} has updated '{}' '{}' seconds ago, actualization needed = {}", ctx.claims("subjectId"), ctx.id(), attrName, (now - actTime), ((now - actTime) > ACT_TIME_IN_SEC));
            return ((now - actTime) > ACT_TIME_IN_SEC);
          }
        }
    }

    /* Template for multi-attribute pipe */
    private StrategyState enterFio(final Context ctx) {
      String uri = "https://loop.dev.identityblitz.com/blitz/pipes/attrs/act?id=enter_fio&appId=my_id_1";
      Set<String> claims = new HashSet<String>(){{
        add("instanceId");
        add("firstName");
        add("lastName");
        add("middleName"); 
      }};
      Set<String> scopes = new HashSet<String>(){{
        add("openid");
      }};
      return StrategyState.ENOUGH_BUILDER()
         .withPipe(uri, "my_id_1", scopes, claims)
         .build(); 
    }
}
