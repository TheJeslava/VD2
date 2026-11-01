"""仅修复实验指定的业务约束，不代表生产应用的完整安全方案。"""


def reset_password(body, session, store):
    if not (session.get('captcha_passed') is True):
        return {'status': 403}
    store.change_password(session['user_id'], body['password'])
    session['captcha_passed'] = False
    return {'status': 200}


def reset_password_client_flag(body, session, store):
    if not (session.get('captcha_passed') is True):
        return {'status': 403}
    store.change_password(session['user_id'], body['password'])
    session['captcha_passed'] = False
    return {'status': 200}


def update_order(body, session, store):
    order = store.get_order(body['order_id'])
    if not (order['owner_id'] == session['user_id']):
        return {'status': 403}
    store.update_order(order['id'], body['memo'])
    return {'status': 200}


def purchase(body, session, store):
    quantity = body['quantity']
    if not (quantity > 0):
        return {'status': 403}
    store.purchase(session['user_id'], quantity)
    return {'status': 200}
