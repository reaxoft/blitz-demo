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
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import com.identityblitz.idp.login.authn.flow.api.*;
import com.identityblitz.idp.login.authn.flow.Context;
import com.identityblitz.idp.login.authn.flow.Strategy;
import com.identityblitz.idp.login.authn.flow.StrategyState;
import com.identityblitz.idp.login.authn.flow.StrategyBeginState;
import com.identityblitz.idp.login.authn.flow.LCookie;
import com.identityblitz.idp.login.authn.flow.LUserAgent;
import com.identityblitz.idp.login.authn.flow.LBrowser;
import com.identityblitz.idp.flow.common.api.*;
import com.identityblitz.idp.flow.dynamic.*;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import java.lang.invoke.LambdaMetafactory;
import java.util.function.Consumer;
import static com.identityblitz.idp.login.authn.flow.StrategyState.*;

public class AddGroupsToToken implements Strategy {

    private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.dynamic");

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
        if(reqFactor == null || reqFactor == ctx.justCompletedFactor()) {
            List<String> grps = new ArrayList<String>();
            int groupListIdx = 0;
            while (groupListIdx > -1) {
              String group = ctx.claims("memberOf.[" + groupListIdx + "]");
              logger.debug("### group [" + groupListIdx + "] = " + group);
              if (group == null) {
                groupListIdx = -1;
              } else {
                grps.add(ctx.claims("memberOf.[" + groupListIdx + "]"));
                groupListIdx ++;
              }
            }
	  		LClaimsBuilder  claimsBuilder = ctx.claimsBuilder();
          	if (grps.size() > 0) {
            	claimsBuilder.addClaim("grps", grps);
            }
            LClaims claims = claimsBuilder.build();
            return StrategyState.ENOUGH_BUILDER()
                .withClaims(claims)
                .build();
        } else
            return StrategyState.MORE(new String[]{});
    }
}
