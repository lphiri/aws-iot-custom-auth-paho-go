
export const handler = async (event, context, callback) => {

    let event_str = JSON.stringify(event);
    console.log('Complete event :' + event_str);
    let protocolData = event.protocolData;
    let accountId = context.invokedFunctionArn.split(":")[4];
    let region = context.invokedFunctionArn.split(":")[3];
    if (protocolData === undefined) {
        console.log('No protocolData..assume CLI test');
        let statement = generateDenyPolicy(accountId, region)
        callback(null, generateAuthResponse(statement));

    } else {
        let resp = validateToken(event, accountId, region)
        callback(null, generateAuthResponse(resp.statement));
    }

};

const CLIENT_ID_KEY = "client-id"
const AUTH_GROUP_KEY = "auth-group"
const ADMIN_AUTH_GROUP = "admin"
const CLIENT_AUTH_GROUP = "client"
const ALLOW_EFFECT = "Allow"
const DENY_EFFECT = "Deny"

//IoT actions
const RECEIVE_ACTION = "iot:Receive"
const SUBSCRIBE_ACTION = "iot:Subscribe"
const PUBLISH_ACTION = "iot:Publish"
const CONNECT_ACTION = "iot:Connect"
const ALL_ACTIONS = "iot:*"


const generateAuthResponse = function (statement) {
    let authResponse = {};
    authResponse.isAuthenticated = true;
    authResponse.principalId = "principalId";

    let policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = statement;
    authResponse.policyDocuments = [policyDocument];
    authResponse.disconnectAfterInSeconds = 3600; //TODO 
    authResponse.refreshAfterInSeconds = 600; //TODO
    console.log('authResponse --> ' + JSON.stringify(authResponse));
    return authResponse;
}

const validateToken = function (event, accountId, region) {

    let resp = {}
    resp.clientId = event.protocolData.mqtt.clientId
    if (event.signatureVerified) {
        let token = event.token
        //get clientid from token and compare with claimed id
        //check token expiry
        console.log(token)
        let claims = parseToken(token)
        if (claims != null) {
            if (claims[CLIENT_ID_KEY] != resp.clientId) {
                console.log("client id does not match signed claim")
                resp.statement = generateDenyPolicy(accountId, region)
                return resp
            }
            if (claims[AUTH_GROUP_KEY] === CLIENT_AUTH_GROUP) {
                resp.statement = generateClientAllowPolicy(accountId, region, resp.clientId)
            } else if (claims[AUTH_GROUP_KEY] === ADMIN_AUTH_GROUP) {
                resp.statement = generateAdminAllowPolicy(accountId, region, resp.clientId)
            } else {
                resp.statement = generateDenyPolicy(accountId, region)
            }
            return resp
        } else {
            resp.statement = generateDenyPolicy(accountId, region)
            return resp
        }
    } else {
        resp.statement = generateDenyPolicy(accountId, region)
        return resp
    }
}

const parseToken = function (token) {
    try {
        // only checking claims  because we depend on signature check from AWS
        let claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())
        console.log("Claims : " + JSON.stringify(claims))
        if (claims["exp"]) {
            const d = new Date(0);
            d.setUTCSeconds(claims["exp"]);
            let now = new Date()
            if (now > d) {
                console.log("Token expired " + d)
                return null
            }
        } else {
            console.log("Token claim missing expiry date!")
            return null
        }
        if (claims[CLIENT_ID_KEY] && claims[AUTH_GROUP_KEY]) {
            return claims
        } else {
            console.log("Token claim missing group.")
            return null
        }
    }
    catch (e) {
        console.log("Failed to parse token.")
        return null;
    }
}

const generateRule = function (effect, action, resource, condition) {
    const rule = {}
    rule.Effect = effect
    rule.Action = action
    rule.Resource = resource
    if (condition) {
        rule.Condition = condition
    }
    return rule
}

const generateConnectAllowRule = function (accountId, region, clientId) {

    return generateRule(ALLOW_EFFECT, CONNECT_ACTION, `arn:aws:iot:${region}:${accountId}:client/${clientId}`, null)
}


const generateDenyPolicy = function (account, region) {
    let fullResource = "arn:aws:iot:" + region + ":" + account + ":*";
    return generateRule(DENY_EFFECT, ALL_ACTIONS, [fullResource])

}


const generateAdminAllowPolicy = function (accountId, region, clientId) {
    let rules = []
    rules.push(generateConnectAllowRule(accountId, region, clientId))
    //Admin clients must be able to publish to all other clients' "in" topics
    let publishTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/*/control/in`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/*/data/in`
    ]
    rules.push(generateRule(ALLOW_EFFECT, PUBLISH_ACTION, publishTopics, null))
    //Admin clients must be able to subscribe to all other clients' "out" topics
    let subscribeTopicFilters = [
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/*/control/out`,
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/*/data/out`
    ]
    rules.push(generateRule(ALLOW_EFFECT, SUBSCRIBE_ACTION, subscribeTopicFilters, null))
    //Admin clients must be able to read data in all clients' "out" topics
    let subscribeTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/*/control/out`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/*/data/out`
    ]
    rules.push(generateRule(ALLOW_EFFECT, RECEIVE_ACTION, subscribeTopics, null))
    return rules
}

const generateClientAllowPolicy = function (accountId, region, clientId) {
    let rules = []
    rules.push(generateConnectAllowRule(accountId, region, clientId))
    //Clients must be able to publish to their own "out" topics
    let publishTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}}/control/out`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/data/out`
    ]
    rules.push(generateRule(ALLOW_EFFECT, PUBLISH_ACTION, publishTopics, null))
    //Clients must be able to subscribe to their own "in" topics
    let subscribeTopicFilters = [
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/${clientId}/control/in`,
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/${clientId}/data/in`
    ]
    rules.push(generateRule(ALLOW_EFFECT, SUBSCRIBE_ACTION, subscribeTopicFilters, null))
    //Clients must be able to read data in their own "in" topics
    let subscribeTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/control/in`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/data/in`
    ]
    rules.push(generateRule(ALLOW_EFFECT, RECEIVE_ACTION, subscribeTopics, null))
    return rules

}

