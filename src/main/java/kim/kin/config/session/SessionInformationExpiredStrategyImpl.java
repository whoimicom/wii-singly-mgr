package kim.kin.config.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import kim.kin.utils.KkConstant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author choky
 */
@Component
public class SessionInformationExpiredStrategyImpl implements SessionInformationExpiredStrategy {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
        event.getResponse().setContentType(KkConstant.CONTENT_TYPE_JSON_UTF8);
        event.getResponse().getWriter().write(mapper.writeValueAsString(new ResponseEntity<Object>("SessionInformationExpired", HttpStatus.BAD_REQUEST)));
    }

}