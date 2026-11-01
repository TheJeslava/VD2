"""模拟缺少外部中间件的审计输入；不导入、不执行这个文件。"""

from unavailable_application import authorize_request


def reset_password(body, session, store):
    authorize_request(body, session)
    store.change_password(session['user_id'], body['password'])


def update_order(body, session, store):
    authorize_request(body, session)
    order = store.get_order(body['order_id'])
    store.update_order(order['id'], body['memo'])


def purchase(body, session, store):
    authorize_request(body, session)
    quantity = body['quantity']
    store.purchase(session['user_id'], quantity)
