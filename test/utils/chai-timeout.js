import pTimeout from 'p-timeout';

export default ({Assertion}, utils) => {
	utils.addMethod(Assertion.prototype, 'timeout', async function (timeout) {
		let timeouted = false;
		await pTimeout(this._obj, timeout, () => {
			timeouted = true;
		});
		return this.assert(
			timeouted,
			'expected promise to timeout but it was resolved',
			'expected promise not to timeout but it timed out'
		);
	});
};
