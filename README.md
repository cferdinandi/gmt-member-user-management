# GMT Courses User Management
User processes for GMT Courses.

## Required Environment Variables

```bash
SetEnv CHECKOUT_URL <url-for-checkout-page>
SetEnv CHECKOUT_USERNAME <basic-auth-username>
SetEnv CHECKOUT_PW <basic-auth-password>
SetEnv COURSE_DATA <course-data-filename>
SetEnv SIGNUP_URL <url-for-signup-page>
SetEnv VALIDATE_URL <url-for-user-validation-page>
SetEnv MIN_PASSWORD_LENGTH <min-password-length>
SetEnv RESET_PW_URL <url-for-password-reset-form>
SetEnv FRONTEND_URL <url-for-the-frontend> # if you want to redirect users away
SetEnv API_ORIGINS <url-for-whitelist-origin>
SetEnv SLACK_TEAM <slack-team-name>
SetEnv SLACK_TOKEN <slack-api-token>
```


## Endpoints

Endpoint use [the WP Ajax endpoint](https://developer.wordpress.org/reference/hooks/wp_ajax_action/) with `action` hooks.

### Example JavaScript Call

```js
fetch('/wp-admin/admin-ajax.php', {
	method: 'POST',
	headers: {
		'X-Requested-With': 'XMLHttpRequest',
		'Content-type': 'application/x-www-form-urlencoded'
	},
	body: 'action={ACTION_TYPE}'
}).then(function (response) {
	if (response.ok) {
		return response.json();
	}
	throw new Error(response);
}).then(function (data) {

	// Response data
	console.log(data);

}).catch(function (error) {

	// Error
	console.warn(error);

});
```

### Actions

- `gmt_member_is_logged_in` - Check if the current user is logged in.
- `gmt_member_login` - Log a user in.
- `gmt_member_logout` - Log the current user out.
- `gmt_member_change_password` - Update a user's password.
- `gmt_member_lost_password` - Send a lost password reset email.
- `gmt_member_reset_password` - Reset a lost password.
- `gmt_member_is_reset_key_valid` - Check if a reset key is valid.
- `gmt_member_slack` - Register a user with Slack.