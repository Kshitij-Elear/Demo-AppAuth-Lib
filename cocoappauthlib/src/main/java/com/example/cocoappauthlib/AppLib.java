package com.example.cocoappauthlib;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.text.TextUtils;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.auth0.android.jwt.JWT;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class AppLib extends AppCompatActivity {
    private static String redirectUriS = "";
    private static String action = "";
    private static final String LOG_TAG = "AppAuth Impementation: ";
    private static final String SHARED_PREFERENCES_NAME = "AuthStatePreference";
    private static final String AUTH_STATE = "AUTH_STATE";
    private static final String USED_INTENT = "USED_INTENT";
    private static AuthState mAuthState;
    private static String message = "";
    private static Context context;
    private static String className;
    protected static String msg = "message";

    public AppLib() {

    }

    public AppLib (Context context, String className) {
        this.context = context;
        this.className = className;
    }

    protected void get_auth_code(String clientId, String scopes) {
        final String packageName = context.getPackageName();

        AuthorizationServiceConfiguration serviceConfiguration = new AuthorizationServiceConfiguration(
                Uri.parse("https://api.elear.solutions/oauth/authorize"),
                Uri.parse("https://api.elear.solutions/oauth/token")
        );

        redirectUriS = packageName + ":/oauth2callback";

        Uri redirectUri = Uri.parse(redirectUriS);

        AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
                serviceConfiguration,
                clientId,
                AuthorizationRequest.RESPONSE_TYPE_CODE,
                redirectUri
        );
        builder.setScopes(scopes);
        AuthorizationRequest request = builder.build();

        AuthorizationService authorizationService = new AuthorizationService(context);

        action = packageName + ".HANDLE_AUTHORIZATION_RESPONSE";

        Intent postAuthorizationIntent = new Intent(action);
        postAuthorizationIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(context, request.hashCode(), postAuthorizationIntent, 0);
        authorizationService.performAuthorizationRequest(request, pendingIntent);

        // prevent memory leaks
        authorizationService.dispose();
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.w(LOG_TAG, "AppLib resume");
        Intent intent = getIntent();
        get_access_token(intent);
    }

    private void get_access_token(Intent intent) {
        // obtaining AuthorizationResponse from intent
        final AuthorizationResponse response = AuthorizationResponse.fromIntent(intent);
        AuthorizationException error = AuthorizationException.fromIntent(intent);
        // to store details of authorization details
        final AuthState authState = new AuthState(response, error);

        // we change Authcode for refresh and access tokens and update AuthState
        // instance with the response

        if (response != null) {
            new AsyncTask<AuthState, Void, Void>() {

                @Override
                protected Void doInBackground(final AuthState... authStates) {
                    Log.i(LOG_TAG, String.format("Handled Authorization Response %s ", authStates[0].toJsonString()));
                    AuthorizationService service = new AuthorizationService(context.getApplicationContext());
                    service.performTokenRequest(response.createTokenExchangeRequest(), new AuthorizationService.TokenResponseCallback() {
                        @Override
                        public void onTokenRequestCompleted(@Nullable TokenResponse tokenResponse, @Nullable AuthorizationException exception) {
                            if (exception != null) {
                                Log.w(LOG_TAG, "Token Exchange failed", exception);
                            } else {
                                if (tokenResponse != null) {
                                    authStates[0].update(tokenResponse, exception);
                                    Log.i(LOG_TAG, String.format("Token Response [ Access Token: %s, ID Token: %s ]", tokenResponse.accessToken, tokenResponse.refreshToken));
                                    persistAuthState(authStates[0]);

                                    Intent cIntent = null;
                                    try {
//                                        cIntent = new Intent(context.getApplicationContext(), Class.forName(context.getClass().getName()));
                                        cIntent = new Intent(context.getApplicationContext(), Class.forName(context.getPackageName()+"."+className));
                                    } catch (ClassNotFoundException e) {
                                        e.printStackTrace();
                                    }
                                    cIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
                                    context.startActivity(cIntent);
                                }
                            }
                        }
                    });
                    return null;
                }
            }.execute(authState);


        } else {
            Log.w(LOG_TAG, "Nothing returned by the browser");
        }
    }

    protected static boolean get_user_info() {
        if (null == (mAuthState = restoreAuthState())) {
            return false;
        }
        Log.w(LOG_TAG, "Exp Time: "+mAuthState.getAccessTokenExpirationTime());
        Log.w(LOG_TAG, "Curr Time: "+ (System.currentTimeMillis()+ 60000L));
        if (mAuthState.getNeedsTokenRefresh()) {
            mAuthState.createTokenRefreshRequest();
            Log.i(LOG_TAG,"Access Token Refreshed.");
        } else {
            if (null == mAuthState.getRefreshToken()) {
                Toast.makeText(context, "Refresh token is null.", Toast.LENGTH_SHORT).show();
                return false;
            }
        }
        String token = mAuthState.getAccessToken();
        Log.w(LOG_TAG, token);
        JWT jwt = new JWT(token);
        String subject = jwt.getSubject();
        Log.i(LOG_TAG,"Subject: "+subject);
        final String apiUrl = "https://api.elear.solutions/user-manager/users/" + subject;
        // getting a fresh token and updating the UI in background through asynctask
        mAuthState.performActionWithFreshTokens(new AuthorizationService(context), new AuthState.AuthStateAction() {
            @Override
            public void execute(@Nullable String accessToken, @Nullable String idToken, @Nullable AuthorizationException exception) {
                new AsyncTask<String, Void, JSONObject>() {
                    @Override
                    protected JSONObject doInBackground(String... tokens) {
                        OkHttpClient client = new OkHttpClient.Builder()
                                .connectTimeout(5, TimeUnit.MINUTES)
                                .writeTimeout(5,TimeUnit.MINUTES)
                                .readTimeout(5, TimeUnit.MINUTES)
                                .build();

                        Request request = new Request.Builder()
                                .url(apiUrl)
                                .addHeader("Authorization", String.format("Bearer %s", tokens[0]))
                                .build();

                        try {
                            Response response = client.newCall(request).execute();
                            String jsonBody = response.body().string();
                            Log.i(LOG_TAG, String.format("User Info Response %s", jsonBody));
                            return new JSONObject(jsonBody);
                        } catch (Exception exception) {
                            Log.w(LOG_TAG, exception);
                        }
                        return null;
                    }

                    @Override
                    protected void onPostExecute(JSONObject userInfo) {
                        if (userInfo != null) {
                            String Name = userInfo.optString("firstName", null);
                            String Loc = userInfo.optString("username", null);

                            if (!TextUtils.isEmpty(Name)) {
                                //mName.setText(Name);
                                Log.i(LOG_TAG, "Name: " + Name);
                            }
                            if (!TextUtils.isEmpty(Loc)) {
                                //mLoc.setText(Loc);
                                Log.i(LOG_TAG, "UserId: " + Loc);
                            }

                            if (userInfo.has("error")) {
                                message = String.format("%s [%s]", "API Call Failed.", userInfo.optString("error_description", "No description"));
                            } else {
                                message = "API Call Successful.";
                                // sending answer as broadcast through intent
                                Intent Bintent = new Intent(msg);
                                Bintent.putExtra("info", userInfo.toString());
                                LocalBroadcastManager.getInstance(context).sendBroadcast(Bintent);
                            }
                            Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
                        } else {
                            message = "User Info Null";
                            Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
                        }
                    }
                }.execute(accessToken);
            }
        });
        Log.w(LOG_TAG, message);



        return !message.equals("User Info Null") && !message.equals("error");
    }

    // to save and load authstate object, desgned can be changed according to our app
    private static void persistAuthState(@NonNull AuthState authState) {
        context.getApplicationContext().getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE).edit()
                .putString(AUTH_STATE, authState.toJsonString())
                .commit();
    }

    private static AuthState restoreAuthState() {
        String jsonString = context.getApplicationContext().getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
                .getString(AUTH_STATE, null);
        if (!TextUtils.isEmpty(jsonString)) {
            try {
                return AuthState.fromJson(jsonString);
            } catch (JSONException jsonException) {
                // should never happen
            }
        }
        return null;
    }

    // to clear authstate
    protected static void clearAuthState() {
        context.getApplicationContext().getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
                .edit()
                .remove(AUTH_STATE)
                .apply();
    }
}