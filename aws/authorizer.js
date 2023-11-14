
export const handler = async (event, context, callback) => {

    //Event data passed to Lambda function
    let event_str = JSON.stringify(event);
    console.log('Complete event :' + event_str);

    //Read protocolData from the event json passed to Lambda function
    let protocolData = event.protocolData;
    console.log('protocolData value---> ' + protocolData);

    //Get the dynamic account ID from function's ARN to be used
    // as full resource for IAM policy
    let accountId = context.invokedFunctionArn.split(":")[4];
    console.log("ACCOUNT_ID---" + accountId);

    //Get the dynamic region from function's ARN to be used
    // as full resource for IAM policy
    let region = context.invokedFunctionArn.split(":")[3];
    console.log("REGION---" + region);

    //protocolData data will be undefined if testing is done via CLI.
    // This will help to test the set up.
    if (protocolData === undefined) {
        //If CLI testing, pass deny action as this is for testing purpose only.
        console.log('Using the test-invoke-authorizer cli for testing only');
        let statement = generateDenyPolicy(accountId, region)
        callback(null, generateAuthResponse(statement));

    } else {
        let resp = validateToken(event, accountId, region)
        callback(null, generateAuthResponse(resp.statement, resp.principalId));
    }

};


const generateAuthResponse = function (statement, principalId) {
    let authResponse = {};
    authResponse.isAuthenticated = true;
    authResponse.principalId = "principalId";

    let policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = statement;
    authResponse.policyDocuments = [policyDocument];
    authResponse.disconnectAfterInSeconds = 3600;
    authResponse.refreshAfterInSeconds = 600;

    console.log('authResponse --> ' + JSON.stringify(authResponse));
    console.log(JSON.stringify(authResponse.policyDocuments[0]));

    return authResponse;
}

const validateToken = function (event, accountId, region) {

    let resp = {}
    resp.principalId = event.protocolData.mqtt.clientId
    if (event.signatureVerified) {
        let token = event.token
        //get clientid from token and compare with claimed id
        //check token expiry
        console.log(token)
        resp.statement = generateClientAllowPolicy(accountId, region, resp.principalId)
    } else {
        resp.statement = generateDenyPolicy(accountId, region)
    }
    return resp
}

const generateDenyPolicy = function (account, region) {
    let fullResource = "arn:aws:iot:" + region + ":" + account + ":*";
    return generateRule("Deny", "iot:*", [fullResource])

}

const generateClientAllowPolicy = function (accountId, region, clientId) {
    let rules = []
    rules.push(generateRule("Allow", "iot:Connect", `arn:aws:iot:${region}:${accountId}:*`, null))
    let publishTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/control/out`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/data/out`
    ]
    rules.push(generateRule("Allow", "iot:Publish", publishTopics, null))
    let subscribeTopicFilters = [
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/${clientId}/control/in`,
        `arn:aws:iot:${region}:${accountId}:topicfilter/redhat/insights/${clientId}/data/in`
    ]
    rules.push(generateRule("Allow", "iot:Subscribe", subscribeTopicFilters, null))
    let subscribeTopics = [
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/control/in`,
        `arn:aws:iot:${region}:${accountId}:topic/redhat/insights/${clientId}/data/in`
    ]
    rules.push(generateRule("Allow", "iot:Receive", subscribeTopics, null)) //needed to receive topic data
    return rules

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
