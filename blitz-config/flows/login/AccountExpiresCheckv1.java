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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class AccountExpiresCheck implements Strategy {

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
  if (ctx.claims("expires_at") != null && isExpired(ctx.claims("expires_at")))
    return StrategyState.DENY("account_expired", true);
  Integer reqFactor = (ctx.user() == null) ? null : ctx.user().requiredFactor();
  if(reqFactor == null || reqFactor == ctx.justCompletedFactor())
    return StrategyState.ENOUGH();
  else
    return StrategyState.MORE(new String[]{});
}
  
  public static boolean isExpired(String strDate) {
    try {
      LocalDate now = LocalDate.now();
      LocalDate date = LocalDate.parse(strDate, DateTimeFormatter.BASIC_ISO_DATE);
      return now.isAfter(date);
    } catch (Exception e) {
       throw new RuntimeException(e);
    }
  }
}