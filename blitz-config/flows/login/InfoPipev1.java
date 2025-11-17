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

public class InfoPipe implements Strategy {

    private final Logger logger = LoggerFactory.getLogger("com.identityblitz.idp.flow.dynamic");
	private final static String DOMAIN = "example.com";

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

    @Override public StrategyState next(Context ctx) {
        if (ctx.user() == null || ctx.user().requiredFactor() == null ||
            ctx.user().requiredFactor().equals(ctx.justCompletedFactor()))
            if (requiredNews("user_agreement", ctx)) return showNews("user_agreement", ctx);
            else return StrategyState.ENOUGH();
        else
            return StrategyState.MORE(new String[] {});
    }

    private boolean requiredNews(final String pipeId, final Context ctx) {
        Long readOn = ctx.user().userProps().numProp("pipes.info." + pipeId + ".disagreedOn");
        return (readOn == null || Instant.now().getEpochSecond() - readOn > 30*86400);
    }

    private StrategyState showNews(final String pipeId, final Context ctx) {
        String uri = "https://" + DOMAIN + "/blitz/pipes/info/start?&pipeId=" + pipeId + "&appId=_blitz_profile";
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
