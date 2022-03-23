package example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MockUserInfoEndpointController {
	@GetMapping(value = "/oauth2/userinfo",produces = "application/json")
	String userinfo() {
		return "{\n" +
				"   \"sub\": \"248289761001\",\n" +
				"   \"name\": \"Jane Doe\",\n" +
				"   \"given_name\": \"Jane\",\n" +
				"   \"family_name\": \"Doe\",\n" +
				"   \"preferred_username\": \"j.doe\",\n" +
				"   \"email\": \"janedoe@example.com\",\n" +
				"   \"picture\": \"http://example.com/janedoe/me.jpg\"\n" +
				"  }";
	}
}
